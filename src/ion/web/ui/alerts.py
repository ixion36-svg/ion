"""Alerts: the case side and the playbook region, as server-rendered fragments.

alerts.html is converted a region at a time, in the order scratchpad
alerts_plan.md sets out, and this module grows a route per region. Stage 2
is the case side: the Cases card in the side panel, the slide-out case
panel, the Add-to-Case picker, the case management modal and the AI case
summary. Stage 3 is the playbook region: the executions list in the case
management modal, the Start Playbook picker, the Investigation Playbooks
section of the alert detail modal and its Browse Playbook Library panel.
Stage 4 is the alert queue: the read behind the table, the fallback rows,
the system select and the failed state of the three side lists; its notes
are above its own section at the end of this module. The analytics panels
and the rest of the alert detail modal are later stages and are not in
here.

What the playbook region did, measured against the tree before stage 3:

  * `loadPlaybooksForAlert` fetched recommended playbooks and executions
    in parallel and wrote `recommendedRes.ok ? json : { playbooks: [] }`.
    A 403, a 400 from an instance with no Elasticsearch and an alert with
    no matching playbook all rendered "No matching playbooks for this
    alert". The executions read did the same, so a failed read hid an
    execution that was in progress.

  * `loadCasePlaybookExecutions` wrote `data.executions || []` and said
    "No playbook executions" for a refusal. Its catch did name the failure,
    which is the one place the region told the two apart.

  * `showCasePlaybookPicker` showed a toast and no dialog when the list
    was empty, and offered Start to every reader; POST
    /api/cases/{id}/playbook/{pid}/start carries playbook:execute.

  * The step checkbox in `renderActiveExecution` carried
    `data-args='[..., this.checked ? 'completed' : 'pending']'`, which is
    not JSON. event-delegation.js logs it and returns, so ticking a step
    never reached the server. The fragment passes `$checked`.

  * `togglePlaybookLibrary` tested `panel.style.display !== 'none'` on a
    panel hidden by a class, so the first click hid an already hidden panel
    and the second opened it. The panel uses the `hidden` attribute here.

  * `renderPlaybooksSection` rendered `${p.step_count} steps` and
    `${e.progress_pct}%` as given, "undefined steps" for a row without the
    field. Guarded with `is not none` here.

What the page did, and why each of these is not a cosmetic port:

  * `loadCases` read GET /api/cases and wrote `data.cases || []`, then
    `renderCasesSummary` rendered "No cases" for an empty array. A refusal
    answers `{"detail": ...}`, which has no `cases` key, so a 403 and an
    estate with no cases were the same sentence. Worse, the function
    returned early on `!response.ok`, so on a failed read the card kept
    saying "Loading..." for the life of the page.

  * The Cases badge came from GET /api/cases/facets with
    `(byStatus.open || 0) + (byStatus.acknowledged || 0)`, and on a failed
    facets read fell back to counting the fetched page, which the page's
    own comment says undercounts on any SOC with more than fifty cases. A
    count that could not be read is rendered as unknown here, not as the
    size of the page.

  * The closure badge in the summary keyed on `c.closure_reason`, a field
    the list endpoint's compact row never carried (measured by reading
    `_summary` in case_query_service). The badge never rendered. The row
    carries it now, which is additive to the JSON.

  * `openCasePanel` offered the status and severity selects and the Add
    note form to every reader. All three call endpoints that require
    `case:update`. The page is gated on `alert:read`, so a read-only
    analyst was offered three controls that answer 403. Withheld here.

  * `_renderAcpContent` defaulted a missing severity to "medium" and a
    missing `created_at` to an age of "0m old". Both are confident
    statements about data that was not there.

  * `addToExistingCase` fell back to GET /api/cases/ (trailing slash) when
    its cache was empty. No route matches that path (measured against the
    live route table), and the body it got back is an object with a
    `cases` key, which it assigned to an array variable and then called
    `.filter` on. The picker lists open cases from the server here.

  * `renderCaseManagementModal` was one 170-line template literal. On a
    failed read `showCaseDetail` logged to the console and showed nothing
    at all, so a click on Manage Case did nothing visible.

Why `case:read` on every GET here: that is what GET /api/cases,
/api/cases/facets and /api/cases/{id} carry, read off the route table in
scratchpad alerts_route_perms.json rather than assumed from the page. The
page's own `alert:read` does not imply it. The AI summary POST mirrors a
flow that needed GET /api/cases/{id} (case:read) and then POST
/api/ai/analyze/alert (auth only); the stricter of the two gates it.

Why the mutations stay on fetch: htmx posts form-encoded bodies and the
case routes take Pydantic JSON models. Converting a PATCH to hx-patch
sends form data to a JSON route and gets a 422 visible only in the network
tab. Reads are converted in this stage; the writes keep their fetch calls
and re-request the fragment afterwards.
"""
from __future__ import annotations

import asyncio
import logging
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, TypedDict

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from markupsafe import Markup, escape
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, render_view

logger = logging.getLogger(__name__)

router = APIRouter()

SUMMARY_FRAGMENT = "_fragments/alerts_cases_summary.html"
PANEL_FRAGMENT = "_fragments/alerts_case_panel.html"
PICKER_FRAGMENT = "_fragments/alerts_case_picker.html"
MANAGE_FRAGMENT = "_fragments/alerts_case_manage.html"
AI_SUMMARY_FRAGMENT = "_fragments/alerts_case_ai_summary.html"
CASE_EXECUTIONS_FRAGMENT = "_fragments/alerts_playbook_case_executions.html"
CASE_PLAYBOOK_PICKER_FRAGMENT = "_fragments/alerts_playbook_case_picker.html"
ALERT_PLAYBOOKS_FRAGMENT = "_fragments/alerts_playbooks.html"
PLAYBOOK_LIBRARY_FRAGMENT = "_fragments/alerts_playbook_library.html"

#: What GET /api/cases, GET /api/cases/facets and GET /api/cases/{id} name.
#: Spelled once so these fragments cannot drift into being a softer way in
#: than the endpoints they mirror.
PERMISSION = "case:read"

#: What PATCH /api/cases/{id} and POST /api/cases/{id}/notes carry. The
#: fragments are gated on PERMISSION because they are reads; this only
#: decides whether the status and severity selects and the note form are
#: offered. A select whose PATCH answers 403 is a worse answer than a value.
UPDATE_PERMISSION = "case:update"

#: What POST /api/cases carries. Passed to the page as a fact about the
#: viewer so the create-case forms are not offered to someone whose submit
#: would be refused.
CREATE_PERMISSION = "case:create"

#: What POST /api/alerts/triage/bulk-update and POST
#: /api/elasticsearch/alerts/{id}/close carry. Decides whether the picker
#: offers Add to Case and whether the management modal offers the per-alert
#: closure buttons and, for a case with linked alerts, Close Case As.
TRIAGE_PERMISSION = "alert:triage"

#: What GET /api/cases/{id}/playbook-executions and GET
#: /api/elasticsearch/alerts/{id}/playbook-executions carry. Not
#: playbook:read: the plan's route table shows the two read-shaped
#: executions endpoints demand execute, so the executions fragment and the
#: executions half of the alert section mirror that or they offer a panel
#: that loads a 403. Also what every playbook mutation carries (start, step
#: update, complete), so it decides whether Start and the step controls are
#: offered at all.
PLAYBOOK_EXECUTE_PERMISSION = "playbook:execute"

#: What GET /api/playbooks, GET .../recommended-playbooks and GET
#: .../suggested-playbooks carry. The picker, the alert section and the
#: library panel are gated on it; Start Playbook opens the picker (this)
#: and then starts one (execute), so it needs both.
PLAYBOOK_READ_PERMISSION = "playbook:read"

#: Recommended playbooks the alert section shows, from the page's
#: `.slice(0, 3)`.
RECOMMENDED_SHOWN = 3

#: Characters of a playbook description the library panel shows, from the
#: page's `substring(0, 80)`.
LIBRARY_DESCRIPTION_CHARS = 80

#: ExecutionStatus values this region keys styling and controls on. Spelled
#: here rather than imported so a template cannot drift from the strings
#: the model stores.
EXEC_IN_PROGRESS = "in_progress"
EXEC_COMPLETED = "completed"
EXEC_FAILED = "failed"

#: Step statuses that count as done for the progress figure, as
#: get_case_playbook_executions and PlaybookExecution count them.
STEP_DONE = ("completed", "skipped")

#: Rows the Cases card shows. The page fetched 50 and sliced to 10.
SUMMARY_LIMIT = 10

#: Open and acknowledged cases the picker lists, per status. The page
#: offered whatever its cache of 50 newest cases held, whichever status.
PICKER_LIMIT = 100

#: Linked alerts and observables the slide-out panel lists, from the page's
#: `.slice(0, 25)` and `.slice(0, 50)`.
PANEL_ALERTS_SHOWN = 25
PANEL_OBSERVABLES_SHOWN = 50

#: How long the management modal waits for Ollama before deciding the AI
#: Summary button is not worth offering. The page asked /api/ai/status once
#: per load; this asks per modal, so it must not hang on an unreachable host.
AI_PROBE_SECONDS = 2.0

STATUS_OPTIONS = ("open", "acknowledged", "closed")
SEVERITY_OPTIONS = ("critical", "high", "medium", "low")

#: CaseClosureReason value to the words the page showed for it.
CLOSURE_LABELS = {
    "true_positive": "True Positive",
    "false_positive": "False Positive",
    "benign_true_positive": "Benign True Positive",
    "duplicate": "Duplicate",
    "insufficient_data": "Insufficient Data",
    "not_applicable": "Not Applicable",
}

#: The short form the Cases card badges a closed case with.
CLOSURE_SHORT = {
    "true_positive": "TP",
    "false_positive": "FP",
    "benign_true_positive": "BTP",
    "duplicate": "DUP",
    "insufficient_data": "N/D",
    "not_applicable": "N/A",
}


def _rows(payload: Any, key: str) -> Optional[list]:
    """The list under `key`, or None when the payload is not that shape.

    None is the third outcome. `data.cases || []` turned a refusal, a
    validation error and a genuinely empty collection into the same empty
    list, and all three rendered "No cases".
    """
    if not isinstance(payload, dict):
        return None
    rows = payload.get(key)
    if not isinstance(rows, list):
        return None
    return rows


def closure_label(reason: Any) -> Optional[str]:
    """The words for a closure reason, the raw value for one this page does
    not know, None for no reason at all."""
    value = plain(reason)
    if not value:
        return None
    return CLOSURE_LABELS.get(str(value), str(value))


def closure_short(reason: Any) -> Optional[str]:
    value = plain(reason)
    if not value:
        return None
    return CLOSURE_SHORT.get(str(value), str(value))


def active_total(facets: Any) -> Optional[int]:
    """Open plus acknowledged, or None when the facets are not readable.

    A status missing from `by_status` is a true zero: the service builds
    the dict from a GROUP BY, which omits empty groups. That is different
    from the facets read failing, which is None here and was the size of
    the fetched page in the JavaScript.
    """
    if not isinstance(facets, dict):
        return None
    by_status = facets.get("by_status")
    if not isinstance(by_status, dict):
        return None
    total = 0
    for key in ("open", "acknowledged"):
        count = by_status.get(key, 0)
        if isinstance(count, bool) or not isinstance(count, int):
            return None
        total += count
    return total


def _parse_instant(value: Any) -> Optional[datetime]:
    """An aware datetime from what get_case_detail emits, or None.

    The rows are `isoformat()` of a naive column. A naive value is read as
    UTC, which is what SQLite's func.now() stores and what a Postgres whose
    session timezone is UTC stores. The JavaScript did `new Date(iso)`,
    which parses a zoneless string as the viewer's local time, so the age
    it showed was off by the viewer's offset.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def age_label(created_at: Any, now: Optional[datetime] = None) -> Optional[str]:
    """"3d", "5h" or "12m", as `_renderAcpContent` computed it, or None.

    None when there is no created_at or it does not parse. The JavaScript
    initialised `ageMs` to 0 for a missing timestamp and rendered "0m old",
    a confident age for a case whose creation time it did not have.
    """
    created = _parse_instant(created_at)
    if created is None:
        return None
    now = now or datetime.now(timezone.utc)
    seconds = max(0.0, (now - created).total_seconds())
    if seconds > 86400:
        return f"{int(seconds // 86400)}d"
    if seconds > 3600:
        return f"{int(seconds // 3600)}h"
    return f"{int(seconds // 60)}m"


def observable_text(observable: Any) -> str:
    """`o.value || o.normalized_value || JSON.stringify(o)`, as text."""
    if isinstance(observable, dict):
        for key in ("value", "normalized_value"):
            value = observable.get(key)
            if value:
                return str(value)
        import json

        return json.dumps(observable, sort_keys=True, default=str)
    return str(observable)


_AI_CODE_CLASS = "bg-[rgba(59,130,246,0.1)] py-0.5 px-1 rounded-[3px]"


def format_ai_content(text: Any) -> Markup:
    """The page's `formatAIContent(escapeHtml(text))`, as one function.

    Escaped first, then the six substitutions in the same order the
    JavaScript applied them, so the result is the same markup over the same
    text. The only tags that can appear are the ones the substitutions
    write; the model's own text is escaped before any of them run.
    """
    s = str(escape("" if text is None else str(text)))
    s = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"`(.*?)`", rf'<code class="{_AI_CODE_CLASS}">\1</code>', s)
    s = re.sub(r"^### (.+)$", r'<div class="font-bold mt-2">\1</div>', s, flags=re.M)
    s = re.sub(r"^## (.+)$", r'<div class="font-bold text-[0.9375rem] mt-3">\1</div>',
               s, flags=re.M)
    s = re.sub(r"^- (.+)$", r'<div class="pl-4">&bull; \1</div>', s, flags=re.M)
    s = re.sub(r"^\d+\.\s(.+)$", r'<div class="pl-4">\g<0></div>', s, flags=re.M)
    return Markup(s)


def ai_summary_payload(case: dict) -> dict:
    """The body `aiSummarizeCase` posted to /api/ai/analyze/alert."""
    return {
        "type": "case_summary",
        "case_number": case.get("case_number"),
        "title": case.get("title"),
        "description": case.get("description"),
        "status": case.get("status"),
        "severity": case.get("severity"),
        "evidence_summary": case.get("evidence_summary"),
        "alerts_count": len(case.get("alerts") or []),
        "affected_hosts": case.get("affected_hosts"),
        "affected_users": case.get("affected_users"),
        "triggered_rules": case.get("triggered_rules"),
    }


def kfp_context(case: dict) -> dict:
    """What `checkKFPMatches` reads off the case it is handed.

    The management modal fragment carries this in a data attribute so the
    page can keep calling that function, which belongs to the detail-modal
    stage, without a second GET /api/cases/{id}.
    """
    return {
        "id": case.get("id"),
        "status": case.get("status"),
        "affected_hosts": case.get("affected_hosts") or [],
        "affected_users": case.get("affected_users") or [],
        "triggered_rules": case.get("triggered_rules") or [],
        "observables": [
            {"type": o.get("type"), "value": o.get("value")}
            for o in (case.get("observables") or [])
            if isinstance(o, dict)
        ],
    }


def _can(user: Optional[User], permission: str) -> bool:
    return bool(user and user.has_permission(permission))


async def _ai_available() -> bool:
    """Whether Ollama answers, bounded so an unreachable host cannot hold
    the modal. False on timeout or any error, which is what the page's
    `aiAvailable` resolved to when /api/ai/status failed."""
    try:
        from ion.services.ollama_service import get_ollama_service

        return bool(await asyncio.wait_for(
            get_ollama_service().is_available(), timeout=AI_PROBE_SECONDS
        ))
    except Exception:
        return False


async def _read_case(case_id: int, current_user: User, session: Session) -> dict:
    """The same dict GET /api/cases/{id} returns, by calling its handler.

    Raises HTTPException(404) for a case that does not exist, exactly as
    the endpoint does, and whatever else the endpoint raises.
    """
    from ion.web.case_lifecycle_api import get_case_detail

    return await get_case_detail(case_id, current_user=current_user, session=session)


# ---------------------------------------------------------------------------
# Cases card
# ---------------------------------------------------------------------------


@router.get(
    "/alerts/cases-summary",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def alerts_cases_summary_fragment(
    request: Request,
    session: Session = Depends(get_db_session),
) -> Response:
    """The Cases card rows plus, out of band, the badge in its header.

    Reads through case_query_service.list_cases_page and case_facets, the
    two functions GET /api/cases and GET /api/cases/facets call, so the row
    a reader sees is the row the JSON reports.

    The two reads fail independently, as they did in the JavaScript, and
    each failure is its own outcome: a list that could not be read says so
    in the card and the badge reads unknown; a facets read that failed
    while the list succeeded shows the rows and an unknown badge, where the
    page substituted the size of the page.
    """
    from ion.services import case_query_service as cq

    try:
        payload = cq.list_cases_page(
            session, sort="created_at", order="desc", limit=SUMMARY_LIMIT
        )
        cases = _rows(payload, "cases")
        failed = cases is None
    except Exception:
        logger.exception("Alerts cases summary fragment could not list cases")
        cases, failed = None, True

    facets_failed = False
    total: Optional[int] = None
    try:
        total = active_total(cq.case_facets(session))
        facets_failed = total is None
    except Exception:
        logger.exception("Alerts cases summary fragment could not read facets")
        facets_failed = True

    rows = None
    if cases is not None:
        rows = [
            {**c, "closure_short": closure_short(c.get("closure_reason")),
             "status_value": plain(c.get("status"))}
            for c in cases if isinstance(c, dict)
        ]

    view = {
        "failed": failed,
        "cases": rows,
        "active_total": total,
        "facets_failed": facets_failed,
        "limit": SUMMARY_LIMIT,
    }
    return render_view(request, SUMMARY_FRAGMENT, view)


# ---------------------------------------------------------------------------
# Slide-out case panel
# ---------------------------------------------------------------------------


def _case_view(case: dict, now: Optional[datetime] = None) -> dict:
    """What the panel and the modal both need derived from the case dict.

    Derivations only. The dict itself is the endpoint's and is passed
    through unchanged, so there is no second notion of a case row here.
    """
    alerts = case.get("alerts")
    alerts = alerts if isinstance(alerts, list) else []
    observables = case.get("observables")
    observables = observables if isinstance(observables, list) else []
    notes = case.get("notes")
    notes = notes if isinstance(notes, list) else []
    return {
        "status": plain(case.get("status")),
        "severity": plain(case.get("severity")),
        "age": age_label(case.get("created_at"), now),
        "closure": closure_label(case.get("closure_reason")),
        "alerts": alerts,
        "alerts_shown": alerts[:PANEL_ALERTS_SHOWN],
        "observables": observables,
        "observables_shown": [
            {"text": observable_text(o),
             "type": o.get("type") if isinstance(o, dict) else None,
             "context": o.get("context") if isinstance(o, dict) else None}
            for o in observables[:PANEL_OBSERVABLES_SHOWN]
        ],
        "notes": notes,
    }


@router.get(
    "/alerts/case-panel/{case_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def alerts_case_panel_fragment(
    request: Request,
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The slide-out panel body, plus its header out of band.

    Three outcomes, where openCasePanel had a loading string, a body and a
    catch that printed the exception message:

      missing  the case does not exist. 200 rather than the endpoint's
               404, because htmx does not swap a 404 and the previous
               case's body would stay on screen under this case's id. The
               header is swapped too, so nothing of the previous case
               remains.
      failed   this fragment or the read raised. The body says so and
               names nothing about the case, because the read did not
               produce one.
      data     the case.

    `can_update` is derived from the viewer and decides whether the status
    and severity selects and the note form are offered.
    """
    can_update = _can(current_user, UPDATE_PERMISSION)

    def answer(ctx: dict) -> Response:
        return render_view(request, PANEL_FRAGMENT,
                           {"case_id": case_id, "can_update": can_update,
                            "status_options": STATUS_OPTIONS,
                            "severity_options": SEVERITY_OPTIONS, **ctx})

    try:
        case = await _read_case(case_id, current_user, session)
    except HTTPException as exc:
        if exc.status_code == 404:
            return answer({"failed": False, "missing": True, "case": None, "view": None})
        logger.exception("Alerts case panel fragment refused for case %s", case_id)
        return answer({"failed": True, "missing": False, "case": None, "view": None})
    except Exception:
        logger.exception("Alerts case panel fragment could not read case %s", case_id)
        return answer({"failed": True, "missing": False, "case": None, "view": None})

    return answer({"failed": False, "missing": False, "case": case,
                   "view": _case_view(case)})


# ---------------------------------------------------------------------------
# Add to Case picker
# ---------------------------------------------------------------------------


def open_cases(session: Session) -> dict:
    """Open and acknowledged cases, newest first within each status.

    Two calls to the same list function GET /api/cases uses, because its
    status filter takes one value. `truncated` says whether either status
    had more than PICKER_LIMIT, so a picker that cannot show every open
    case says so instead of looking complete.
    """
    from ion.services import case_query_service as cq

    cases: list = []
    total = 0
    truncated = False
    for status in ("open", "acknowledged"):
        page = cq.list_cases_page(
            session, status=status, sort="created_at", order="desc",
            limit=PICKER_LIMIT,
        )
        rows = _rows(page, "cases")
        if rows is None:
            raise ValueError(f"list_cases_page returned no case list for {status}")
        cases.extend(r for r in rows if isinstance(r, dict))
        total += int(page.get("total") or 0)
        truncated = truncated or bool(page.get("has_more"))
    return {"cases": cases, "total": total, "truncated": truncated}


@router.get(
    "/alerts/case-picker",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
def alerts_case_picker_fragment(
    request: Request,
    selected: int = Query(0, ge=0, description="How many alerts are selected"),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The Add Alerts to Case modal.

    `selected` is the page's selection count, client state passed as a
    request parameter so the sentence "Adding N alert(s) to case" can be
    rendered here. The ids themselves stay with confirmAddToCase, whose
    POST is a JSON body and stays on fetch.

    Add to Case is offered only with alert:triage, which is what
    POST /api/alerts/triage/bulk-update requires.
    """
    can_add = _can(current_user, TRIAGE_PERMISSION)
    try:
        listing = open_cases(session)
    except Exception:
        logger.exception("Alerts case picker fragment could not list open cases")
        view = {"failed": True, "cases": None, "total": None,
                 "truncated": False, "selected": selected,
                 "can_add": can_add}
        return render_view(request, PICKER_FRAGMENT, view)
    view = {"failed": False, "selected": selected, "can_add": can_add,
             **listing}
    return render_view(request, PICKER_FRAGMENT, view)


# ---------------------------------------------------------------------------
# Case management modal
# ---------------------------------------------------------------------------


@router.get(
    "/alerts/case-manage/{case_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def alerts_case_manage_fragment(
    request: Request,
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The case management modal, the overlay included.

    Every control is gated on the permission its endpoint carries:

      status and severity selects, Add Note,
        Escalate to DFIR-IRIS                  case:update
      per-alert closure buttons                alert:triage
      Close Case As                            alert:triage when the case
                                               has linked alerts (the page
                                               closes the first alert and
                                               the backend closes the rest
                                               and the case), case:update
                                               when it has none and PATCHes
                                               the case directly
      Playbook executions section              playbook:execute, which the
                                               executions GET demands
      Start Playbook                           playbook:read and
                                               playbook:execute

    The page offered all of them to every reader.

    AI Summary is offered when Ollama answers within AI_PROBE_SECONDS,
    where the page used a flag from one /api/ai/status call at load.
    """
    flags = {
        "can_update": _can(current_user, UPDATE_PERMISSION),
        "can_triage": _can(current_user, TRIAGE_PERMISSION),
        "can_execute_playbooks": _can(current_user, PLAYBOOK_EXECUTE_PERMISSION),
    }
    flags["can_start_playbook"] = (
        flags["can_execute_playbooks"] and _can(current_user, PLAYBOOK_READ_PERMISSION)
    )

    def answer(ctx: dict) -> Response:
        view = {"case_id": case_id, "status_options": STATUS_OPTIONS,
                "severity_options": SEVERITY_OPTIONS, **flags, **ctx}
        return render_view(request, MANAGE_FRAGMENT, view)

    try:
        case = await _read_case(case_id, current_user, session)
    except HTTPException as exc:
        if exc.status_code == 404:
            return answer({"failed": False, "missing": True, "case": None,
                           "view": None, "ai_available": False,
                           "can_close": False, "kfp": None})
        logger.exception("Alerts case manage fragment refused for case %s", case_id)
        return answer({"failed": True, "missing": False, "case": None,
                       "view": None, "ai_available": False,
                       "can_close": False, "kfp": None})
    except Exception:
        logger.exception("Alerts case manage fragment could not read case %s", case_id)
        return answer({"failed": True, "missing": False, "case": None,
                       "view": None, "ai_available": False,
                       "can_close": False, "kfp": None})

    view = _case_view(case)
    can_close = flags["can_triage"] if view["alerts"] else flags["can_update"]
    return answer({
        "failed": False,
        "missing": False,
        "case": case,
        "view": view,
        "can_close": can_close,
        "ai_available": await _ai_available(),
        "kfp": kfp_context(case),
    })


# ---------------------------------------------------------------------------
# AI case summary
# ---------------------------------------------------------------------------


@router.post(
    "/alerts/case-summary/{case_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION))],
)
async def alerts_case_ai_summary_fragment(
    request: Request,
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The AI case summary, rendered into #ai-case-summary-{id}.

    Calls the same handler POST /api/ai/analyze/alert runs, with the same
    payload aiSummarizeCase built from GET /api/cases/{id}, so the prompt,
    the PII tokenisation and the history context are one computation.

    Outcomes: the case is missing; the AI service refused (a 503 from the
    handler, with its detail); the summary could not be produced for any
    other reason; the summary. The page had one error string for the
    middle three: "AI summary failed: <exception message>".
    """
    from ion.web.ai_api import analyze_alert

    def answer(ctx: dict) -> Response:
        return render_view(request, AI_SUMMARY_FRAGMENT,
                           {"case_id": case_id, **ctx})

    try:
        case = await _read_case(case_id, current_user, session)
    except HTTPException as exc:
        if exc.status_code == 404:
            return answer({"missing": True, "unavailable": None, "failed": False,
                           "analysis": None, "model": None})
        logger.exception("AI case summary fragment refused for case %s", case_id)
        return answer({"missing": False, "unavailable": None, "failed": True,
                       "analysis": None, "model": None})
    except Exception:
        logger.exception("AI case summary fragment could not read case %s", case_id)
        return answer({"missing": False, "unavailable": None, "failed": True,
                       "analysis": None, "model": None})

    try:
        result = await analyze_alert(
            ai_summary_payload(case), current_user=current_user, session=session
        )
    except HTTPException as exc:
        # The handler raises 503 both for "not available" and for an
        # OllamaError during the chat, with the reason in detail.
        return answer({"missing": False, "unavailable": str(exc.detail or "AI service not available"),
                       "failed": False, "analysis": None, "model": None})
    except Exception:
        logger.exception("AI case summary fragment failed for case %s", case_id)
        return answer({"missing": False, "unavailable": None, "failed": True,
                       "analysis": None, "model": None})

    analysis = result.get("analysis") if isinstance(result, dict) else None
    model = result.get("model") if isinstance(result, dict) else None
    return answer({
        "missing": False,
        "unavailable": None,
        "failed": False,
        # None, not an empty Markup: a model that answered with no text is
        # a third thing and the template says so.
        "analysis": format_ai_content(analysis) if analysis else None,
        "model": model,
    })


# ---------------------------------------------------------------------------
# Playbooks
# ---------------------------------------------------------------------------


def _count(value: Any) -> Optional[int]:
    """An int, or None for anything that is not one.

    bool is excluded on purpose: `True` is an int in Python and a count of
    1 is not what a flag means. `${e.progress_pct}%` rendered "undefined%"
    for a row without the field; None here renders as not counted.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _number(value: Any) -> Optional[float]:
    """A real number, or None. Same bool rule as `_count`: True is an int
    in Python and a payload carrying a flag where a figure was expected
    must not render as 1.

    This duplicates the one in ui/cases.py. Two pages need it now, so by
    this package's own rule the pair belongs in _shared; that lift touches
    two committed modules and is left for whoever needs it third.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value

def execution_progress(execution: dict) -> dict:
    """completed, total and pct for an execution, computed the way
    get_case_playbook_executions computes them: a step is done when its
    status is completed or skipped, and pct is None, not 0, for a playbook
    with no steps. `renderActiveExecution` wrote 0% for that, which is a
    confident claim about a playbook that cannot progress."""
    playbook = execution.get("playbook")
    steps = playbook.get("steps") if isinstance(playbook, dict) else None
    steps = steps if isinstance(steps, list) else []
    statuses = execution.get("step_statuses")
    statuses = statuses if isinstance(statuses, dict) else {}
    completed = sum(
        1 for s in statuses.values()
        if isinstance(s, dict) and s.get("status") in STEP_DONE
    )
    total = len(steps)
    return {
        "completed": completed,
        "total": total,
        "pct": round(completed / total * 100) if total else None,
    }


def pending_step_ids(execution: dict) -> list:
    """Ids of the steps not yet completed or skipped, in step order.

    `skipRemainingSteps` computed this from a client cache of the last
    executions read. The fragment carries it on the execution block so the
    function reads it off the DOM instead and the cache goes.
    """
    playbook = execution.get("playbook")
    steps = playbook.get("steps") if isinstance(playbook, dict) else None
    statuses = execution.get("step_statuses")
    statuses = statuses if isinstance(statuses, dict) else {}
    out = []
    for step in steps if isinstance(steps, list) else []:
        if not isinstance(step, dict) or step.get("id") is None:
            continue
        state = statuses.get(str(step.get("id")))
        if isinstance(state, dict) and state.get("status") in STEP_DONE:
            continue
        out.append(step.get("id"))
    return out


def execution_view(execution: dict) -> dict:
    """What the active-execution block needs, derived from the endpoint's
    dict. The dict itself is passed through; these are derivations."""
    playbook = execution.get("playbook")
    playbook = playbook if isinstance(playbook, dict) else None
    steps = playbook.get("steps") if playbook else None
    statuses = execution.get("step_statuses")
    statuses = statuses if isinstance(statuses, dict) else {}
    rows = []
    for step in steps if isinstance(steps, list) else []:
        if not isinstance(step, dict):
            continue
        state = statuses.get(str(step.get("id")))
        status = state.get("status") if isinstance(state, dict) else None
        rows.append({
            "id": step.get("id"),
            "title": step.get("title"),
            "is_required": bool(step.get("is_required")),
            "status": status,
            "done": status in STEP_DONE,
            "skipped": status == "skipped",
        })
    return {
        "id": execution.get("id"),
        "playbook_id": execution.get("playbook_id"),
        "playbook": playbook,
        "status": plain(execution.get("status")),
        "steps": rows,
        "progress": execution_progress(execution),
        "pending_step_ids": pending_step_ids(execution),
    }


def active_execution(executions: list) -> Optional[dict]:
    """The first in-progress execution, as `.find(e => e.status ===
    'in_progress')` chose it, or None."""
    for e in executions:
        if isinstance(e, dict) and plain(e.get("status")) == EXEC_IN_PROGRESS:
            return e
    return None


def completed_count(executions: list) -> int:
    return sum(
        1 for e in executions
        if isinstance(e, dict) and plain(e.get("status")) == EXEC_COMPLETED
    )


def recommended_rows(playbooks: list, active: Optional[dict]) -> list:
    """The recommendations the section shows: the active execution's own
    playbook left out (it is shown above as the execution), the first
    RECOMMENDED_SHOWN of the rest."""
    active_id = active.get("playbook_id") if isinstance(active, dict) else None
    rows = [p for p in playbooks if isinstance(p, dict) and p.get("id") != active_id]
    return rows[:RECOMMENDED_SHOWN]


def short_description(text: Any) -> Optional[str]:
    """The first LIBRARY_DESCRIPTION_CHARS of a description with an
    ellipsis when it was cut, None for none."""
    if not text:
        return None
    text = str(text)
    if len(text) > LIBRARY_DESCRIPTION_CHARS:
        return text[:LIBRARY_DESCRIPTION_CHARS] + "..."
    return text


def case_execution_rows(executions: list) -> list:
    """The case executions endpoint's rows with the three counts it adds
    guarded, so a row missing one renders as not counted rather than as
    "undefined/undefined"."""
    rows = []
    for e in executions:
        if not isinstance(e, dict):
            continue
        playbook = e.get("playbook")
        rows.append({
            **e,
            "status_value": plain(e.get("status")),
            "outcome_value": plain(e.get("outcome")),
            "playbook_name": playbook.get("name") if isinstance(playbook, dict) else None,
            "progress_pct": _count(e.get("progress_pct")),
            "completed_steps": _count(e.get("completed_steps")),
            "total_steps": _count(e.get("total_steps")),
        })
    return rows


def library_groups(playbooks: list) -> dict:
    """Recommended (active) and library (inactive) suggestions, as
    `renderPlaybookLibraryPanel` split them. A recommended playbook with an
    execution in progress is left out of its group because the section
    above shows that execution; a library one keeps its row with Start
    disabled, as the page did."""
    recommended, library = [], []
    for p in playbooks:
        if not isinstance(p, dict):
            continue
        row = {**p, "short_description": short_description(p.get("description")),
               "step_count": _count(p.get("step_count"))}
        kind = p.get("suggestion_type")
        if kind == "recommended" and not p.get("has_active_execution"):
            recommended.append(row)
        elif kind == "library":
            library.append(row)
    return {"recommended": recommended, "library": library}


@router.get(
    "/alerts/case-playbook-executions/{case_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PLAYBOOK_EXECUTE_PERMISSION))],
)
def alerts_case_playbook_executions_fragment(
    request: Request,
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The Playbook Executions list in the case management modal.

    Calls the handler GET /api/cases/{id}/playbook-executions runs, which
    also back-fills executions discovered through the case's alerts, so
    the rows here are the rows the JSON reports, including that side
    effect.

    Outcomes: the case is gone (the handler's 404); the read failed; no
    executions; rows. `loadCasePlaybookExecutions` had the last two and
    its catch, and `data.executions || []` folded a refusal into the
    third.
    """
    from ion.web.case_lifecycle_api import get_case_playbook_executions

    def answer(ctx: dict) -> Response:
        return render_view(request, CASE_EXECUTIONS_FRAGMENT,
                           {"case_id": case_id, **ctx})

    try:
        payload = get_case_playbook_executions(case_id, current_user=current_user, session=session)
    except HTTPException as exc:
        if exc.status_code == 404:
            return answer({"missing": True, "failed": False, "executions": None})
        logger.exception("Case playbook executions fragment refused for case %s", case_id)
        return answer({"missing": False, "failed": True, "executions": None})
    except Exception:
        logger.exception("Case playbook executions fragment could not read case %s", case_id)
        return answer({"missing": False, "failed": True, "executions": None})

    executions = _rows(payload, "executions")
    if executions is None:
        logger.error("Case playbook executions for case %s came back without a list", case_id)
        return answer({"missing": False, "failed": True, "executions": None})
    return answer({"missing": False, "failed": False,
                   "executions": case_execution_rows(executions)})


@router.get(
    "/alerts/case-playbook-picker/{case_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PLAYBOOK_READ_PERMISSION))],
)
def alerts_case_playbook_picker_fragment(
    request: Request,
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The Start Playbook picker for a case, the overlay included.

    Lists through the handler GET /api/playbooks?active_only=true runs.
    Start is offered only with playbook:execute, which POST
    /api/cases/{id}/playbook/{pid}/start carries; the page offered it to
    every reader. An empty list is a dialog that says so, where the page
    showed a toast and no dialog.
    """
    from ion.web.api import list_playbooks

    can_start = _can(current_user, PLAYBOOK_EXECUTE_PERMISSION)

    def answer(ctx: dict) -> Response:
        return render_view(request, CASE_PLAYBOOK_PICKER_FRAGMENT,
                           {"case_id": case_id, "can_start": can_start, **ctx})

    try:
        payload = list_playbooks(active_only=True, current_user=current_user, session=session)
        playbooks = _rows(payload, "playbooks")
    except Exception:
        logger.exception("Case playbook picker fragment could not list playbooks")
        playbooks = None
    if playbooks is None:
        return answer({"failed": True, "playbooks": None})
    rows = [{**p, "step_count": _count(p.get("step_count"))}
            for p in playbooks if isinstance(p, dict)]
    return answer({"failed": False, "playbooks": rows})


async def _recommended(alert_id: str, current_user: User, session: Session) -> dict:
    """The recommended-playbooks read as one of four outcomes.

    `missing` is the handler's 404 (the alert is not in Elasticsearch);
    `failed` is any other refusal, with the handler's detail as `error`
    when it gave one (400 "Elasticsearch is not configured" is the usual
    reason on an instance without it), or any other exception with no
    detail; otherwise `playbooks` is the list, possibly empty.
    """
    from ion.web.api import get_recommended_playbooks

    try:
        payload = await get_recommended_playbooks(alert_id, current_user=current_user, session=session)
    except HTTPException as exc:
        if exc.status_code == 404:
            return {"missing": True, "failed": False, "error": None, "playbooks": None}
        return {"missing": False, "failed": True, "error": str(exc.detail or ""), "playbooks": None}
    except Exception:
        logger.exception("Recommended playbooks could not be read for alert %s", alert_id)
        return {"missing": False, "failed": True, "error": None, "playbooks": None}
    playbooks = _rows(payload, "playbooks")
    if playbooks is None:
        return {"missing": False, "failed": True, "error": None, "playbooks": None}
    return {"missing": False, "failed": False, "error": None,
            "playbooks": [p for p in playbooks if isinstance(p, dict)]}


def _alert_executions(alert_id: str, current_user: User, session: Session) -> Optional[list]:
    """The alert's executions, or None when they could not be read."""
    from ion.web.api import get_alert_playbook_executions

    try:
        payload = get_alert_playbook_executions(alert_id, current_user=current_user, session=session)
    except Exception:
        logger.exception("Playbook executions could not be read for alert %s", alert_id)
        return None
    return _rows(payload, "executions")


@router.get(
    "/alerts/playbooks/{alert_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PLAYBOOK_READ_PERMISSION))],
)
async def alerts_playbooks_fragment(
    request: Request,
    alert_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The Investigation Playbooks section of the alert detail modal.

    Two reads, as `loadPlaybooksForAlert` made them, each with its own
    outcome rather than `res.ok ? json : { playbooks: [] }`:

      recommended    GET .../recommended-playbooks, playbook:read, which
                     this route is gated on. Missing alert, failed read
                     (with the reason when the handler gave one), no
                     match, or rows.
      executions     GET .../playbook-executions, playbook:execute. Read
                     only when the viewer has it, and withheld, not
                     empty, when they do not: the active execution and
                     the completed count are then unknown, and the
                     section says so instead of showing nothing.

    Start and the step controls are offered only with playbook:execute,
    which every playbook mutation carries.
    """
    can_execute = _can(current_user, PLAYBOOK_EXECUTE_PERMISSION)
    recommended = await _recommended(alert_id, current_user, session)

    executions: Optional[list] = None
    executions_failed = False
    if can_execute:
        executions = _alert_executions(alert_id, current_user, session)
        executions_failed = executions is None

    active = active_execution(executions) if executions is not None else None
    rows = (recommended_rows(recommended["playbooks"], active)
            if recommended["playbooks"] is not None else None)
    if rows is not None:
        rows = [{**p, "step_count": _count(p.get("step_count"))} for p in rows]

    view = {
        "alert_id": alert_id,
        "can_execute": can_execute,
        "alert_missing": recommended["missing"],
        "recommended_failed": recommended["failed"],
        "recommended_error": recommended["error"],
        "recommended": rows,
        "executions_withheld": not can_execute,
        "executions_failed": executions_failed,
        "active": execution_view(active) if active else None,
        "completed_count": completed_count(executions) if executions is not None else None,
    }
    return render_view(request, ALERT_PLAYBOOKS_FRAGMENT, view)


@router.get(
    "/alerts/playbook-library/{alert_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PLAYBOOK_READ_PERMISSION))],
)
async def alerts_playbook_library_fragment(
    request: Request,
    alert_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The Browse Playbook Library panel under the alert's section.

    Lists through the handler GET .../suggested-playbooks runs. Same four
    outcomes as the recommendations: missing alert, failed read with the
    reason, nothing in the library that matches, or the two groups.
    `togglePlaybookLibrary` had a failure string and `data.playbooks || []`.
    """
    from ion.web.api import get_suggested_playbooks

    can_start = _can(current_user, PLAYBOOK_EXECUTE_PERMISSION)

    def answer(ctx: dict) -> Response:
        return render_view(request, PLAYBOOK_LIBRARY_FRAGMENT,
                           {"alert_id": alert_id, "can_start": can_start, **ctx})

    try:
        payload = await get_suggested_playbooks(alert_id, current_user=current_user, session=session)
    except HTTPException as exc:
        if exc.status_code == 404:
            return answer({"missing": True, "failed": False, "error": None,
                           "recommended": None, "library": None})
        return answer({"missing": False, "failed": True, "error": str(exc.detail or ""),
                       "recommended": None, "library": None})
    except Exception:
        logger.exception("Suggested playbooks could not be read for alert %s", alert_id)
        return answer({"missing": False, "failed": True, "error": None,
                       "recommended": None, "library": None})

    playbooks = _rows(payload, "playbooks")
    if playbooks is None:
        return answer({"missing": False, "failed": True, "error": None,
                       "recommended": None, "library": None})
    return answer({"missing": False, "failed": False, "error": None,
                   **library_groups(playbooks)})


# ---------------------------------------------------------------------------
# The alert queue
# ---------------------------------------------------------------------------
#
# Stage 4. What loadAlerts did, measured against the tree before it:
#
#   * `const incomingAlerts = data.alerts || [];` and then, on the handler's
#     own message branch AND in the catch, the identical
#     `'<div class="empty-state">-</div>'` into top-hosts-list,
#     top-rules-list and top-users-list. A failed Elasticsearch read and a
#     quiet estate rendered the same picture in all three side panels.
#
#   * When the handler reported a message but lab fixtures were present,
#     the fixtures were rendered and the message was dropped, so an
#     instance whose Elasticsearch was unreachable looked like a healthy
#     one with a few alerts.
#
#   * The table was wiped to "Loading alerts..." on every refresh, five
#     minutes apart, so an analyst mid-read lost the rows for the length of
#     the round trip.
#
#   * The system select was rebuilt from the alerts seen so far, in a
#     client Map that lived as long as the page, so filtering by one system
#     emptied the list of every other on a fresh load.
#
#   * The row limit of 500 was never shown. A window with 2,000 alerts
#     rendered as 500 with nothing to say the rest existed.
#
# What stays on the client, and why: the table rows are rendered by
# static/js/alerts-queue.js from `allAlerts`, and the threat banner, the
# stats bar, the attention chips, the analytics panels and the triage batch
# all aggregate from that same array. The plan calls it the data spine and
# says the analytics stage has to give those their own server aggregation
# before the array can go. So this fragment carries the array the JSON
# endpoint produced, in a data block the page reads once, and the rows it
# renders itself are the fallback the module replaces when it is present.
# The side lists follow the client's own filters (search text, severity,
# entity, saved view), and a second server-side definition of that filter
# would be the two-paths-disagree failure the page's own comments warn of,
# so their rows are cloned from a <template> in the page and only their
# failed state comes from here.

QUEUE_FRAGMENT = "_fragments/alerts_queue.html"

#: Stage 6, the analytics drawer.
ANALYTICS_FRAGMENT = "_fragments/alerts_analytics.html"

#: Stage 7, the drawer's systems tab.
SYSTEMS_FRAGMENT = "_fragments/alerts_systems.html"

#: What GET /api/elasticsearch/alerts and POST
#: /api/elasticsearch/alerts-triage/batch carry.
QUEUE_PERMISSION = "alert:read"

#: The page's `limit: 500`. Also the cap the fragment says out loud when
#: the read returned exactly this many, because the endpoint has no way to
#: say there were more.
QUEUE_LIMIT = 500

#: The `hours` the page sent for a window it could not read off the
#: controls: a custom range with no start, or a select value that is not a
#: number. The page did `parseInt(val) || 24`.
QUEUE_DEFAULT_HOURS = 24

#: Columns of the fallback row, for the colspan of a state row. The
#: module's own column count varies with the chooser; these rows do not.
QUEUE_FALLBACK_COLUMNS = 12

#: The `alert-time-range` option value that means the two datetime-local
#: inputs decide the window.
CUSTOM_RANGE = "custom"

#: Status filter values that made the page ask for closed alerts too.
STATUSES_INCLUDING_CLOSED = ("closed", "all")


def _parse_local(value: Any, tz_offset_minutes: Optional[int]) -> Optional[datetime]:
    """A datetime-local control value as an aware UTC instant, or None.

    The control emits "YYYY-MM-DDTHH:MM" (seconds optional) with no zone.
    The page did `new Date(from).toISOString()`, which reads it as the
    viewer's local time. The server cannot know that zone, so the page
    sends `getTimezoneOffset()` in a hidden input and the same arithmetic
    is done here: JavaScript's offset is minutes WEST of UTC, so UTC is
    local plus the offset. With no offset the value is read as UTC, which
    is the one honest reading of a zoneless time.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        local = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if local.tzinfo is not None:
        return local.astimezone(timezone.utc)
    from datetime import timedelta

    return (local + timedelta(minutes=tz_offset_minutes or 0)).replace(tzinfo=timezone.utc)


def _int_or_none(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def queue_window(time_range: str, custom_from: str = "", custom_to: str = "",
                 tz_offset: str = "") -> dict:
    """hours, time_from and time_to for the alerts read, from the raw
    control values, as loadAlerts derived them.

    `custom` with a parseable start sends absolute bounds; `custom` with
    no start falls back to QUEUE_DEFAULT_HOURS, as the page did. Any other
    value is the hours figure, with the same default for one that is not a
    positive integer. `defaulted` says when that fallback was taken, so the
    fragment can say the window it actually read rather than the one the
    control claims.
    """
    offset = _int_or_none(tz_offset)
    if time_range == CUSTOM_RANGE:
        start = _parse_local(custom_from, offset)
        if start is None:
            return {"hours": QUEUE_DEFAULT_HOURS, "time_from": None, "time_to": None,
                    "defaulted": True}
        end = _parse_local(custom_to, offset)
        return {"hours": QUEUE_DEFAULT_HOURS,
                "time_from": start.isoformat().replace("+00:00", "Z"),
                "time_to": end.isoformat().replace("+00:00", "Z") if end else None,
                "defaulted": False}
    hours = _int_or_none(time_range)
    if hours is None or hours <= 0:
        return {"hours": QUEUE_DEFAULT_HOURS, "time_from": None, "time_to": None,
                "defaulted": True}
    return {"hours": hours, "time_from": None, "time_to": None, "defaulted": False}


def include_closed(status: Any) -> bool:
    """Whether the status control's value asked for closed alerts. The
    narrowing to one status stays on the client, because it reads the
    triage status the batch endpoint supplies after the alerts arrive."""
    return status in STATUSES_INCLUDING_CLOSED


def queue_outcome(payload: Any) -> dict:
    """The alerts read as one of four outcomes, from what get_es_alerts
    returns.

      failed    the handler reported a message and no alerts came with it.
                `reason` is its message; `connection_error` says whether it
                was a connection failure or a configuration state.
      degraded  the handler reported a message AND alerts came with it. On
                this handler those are lab fixtures, which it merges in on
                every return path. The page rendered them and dropped the
                message; here both are kept.
      empty     no message, no alerts. A measured zero.
      data      no message, alerts.

    `alerts` is None only for failed, so a template cannot render "no
    alerts" for a read that did not happen. A payload that is not a dict
    or has no list under `alerts` is failed with no reason, because the
    handler did not produce what it promises.
    """
    alerts = _rows(payload, "alerts")
    if alerts is None:
        return {"failed": True, "degraded": False, "reason": None,
                "connection_error": False, "alerts": None, "arkime_enabled": False}
    alerts = [a for a in alerts if isinstance(a, dict)]
    message = payload.get("message")
    reason = str(message) if message else None
    connection_error = bool(payload.get("connection_error"))
    arkime = payload.get("arkime_enabled") is True
    if reason and not alerts:
        return {"failed": True, "degraded": False, "reason": reason,
                "connection_error": connection_error, "alerts": None,
                "arkime_enabled": arkime}
    return {"failed": False, "degraded": bool(reason), "reason": reason,
            "connection_error": connection_error, "alerts": alerts,
            "arkime_enabled": arkime}


def system_options(alerts: Optional[list], known: Optional[list], selected: str) -> list:
    """The system select's options: every registered system, every system
    the alerts carry, and the one currently selected even if neither list
    has it, so the control never stops showing what it is filtering by.

    Sorted by label, case-insensitively, as populateSystemFilterFromAlerts
    sorted them. `known` is list_known_systems' output or None when that
    read failed, in which case the alerts alone supply the list.
    """
    labels: dict[str, str] = {}
    for row in known or []:
        if not isinstance(row, dict):
            continue
        ns = row.get("namespace")
        if ns:
            labels[str(ns)] = str(row.get("display_name") or ns)
    for a in alerts or []:
        ns = a.get("source_system")
        if not ns:
            continue
        label = a.get("cyab_system_name") or a.get("tide_system_name") or ns
        labels[str(ns)] = str(label)
    if selected and selected not in labels:
        labels[selected] = selected
    out = [{"value": ns, "label": label, "selected": ns == selected}
           for ns, label in labels.items()]
    out.sort(key=lambda r: r["label"].lower())
    return out


def _system_badge(a: dict) -> Optional[dict]:
    """What renderSystemBadge in alert-detail.js shows: the CyAB name, else
    the TIDE name, else the namespace, with the tooltip listing all three,
    and a link when the CyAB system has an id. None when the alert names
    no system at all."""
    ns = a.get("source_system")
    cyab = a.get("cyab_system_name")
    tide = a.get("tide_system_name")
    if not ns and not cyab and not tide:
        return None
    display = cyab or tide or ns
    parts = []
    if ns:
        parts.append(f"namespace: {ns}")
    if cyab:
        parts.append(f"CyAB: {cyab}")
    if tide and tide != cyab:
        parts.append(f"TIDE: {tide}")
    return {"display": display, "tooltip": " • ".join(parts) or display,
            "cyab_system_id": a.get("cyab_system_id")}


def queue_rows(alerts: list, triage: Optional[dict], arkime_enabled: bool) -> list:
    """The fallback rows: each alert dict passed through with the
    derivations the row template needs.

    `triage` is the batch endpoint's map or None when it could not be
    read. The two render differently: an alert absent from a map that was
    read has no triage record (dot `triage-none`, no case), while a row
    whose map is None has a triage that was not read (dot
    `triage-unknown`, case "?"). The page's fallback read a client cache
    and showed `none` for both.

    The triage status is taken as the handler emits it: get_batch_triage
    writes `t.status.value`, a string, and the test file pins that on the
    handler. The alert's own status is not so normalised: a lab fixture's
    dict carries the AlertTriageStatus member itself (_fixture_alert_dicts
    passes `t.status` through), and on the one path where it is rendered,
    a fixture whose triage read failed, str(member) would print
    "AlertTriageStatus.OPEN" into the class and the badge. Hence `plain`
    there and not on the triage side.
    """
    rows = []
    for a in alerts:
        t = triage.get(a.get("id")) if isinstance(triage, dict) else None
        t = t if isinstance(t, dict) else None
        triage_status = t.get("status") if t else None
        has_network = bool(a.get("network_community_id") or a.get("source_ip")
                           or a.get("destination_ip") or a.get("arkime_node"))
        rows.append({
            **a,
            "triage_read": triage is not None,
            "triage_status": triage_status,
            "effective_status": triage_status or plain(a.get("status")),
            "case_number": t.get("case_number") if t else None,
            "case_title": t.get("case_title") if t else None,
            "system_badge": _system_badge(a),
            "arkime": bool(arkime_enabled and has_network),
            "arkime_by_ip": bool(arkime_enabled and has_network and not a.get("network_community_id")),
        })
    return rows


async def _triage_map(alert_ids: list, current_user: User, session: Session) -> Optional[dict]:
    """The batch triage endpoint's map for these ids, or None when it could
    not be read. No `es_statuses` is passed, so the handler's Kibana-to-ION
    status sync does not run: this is a read. The page's loadTriageBatch
    still runs after the swap and does the sync as before."""
    from ion.web.api import BatchTriageRequestWithStatus, get_batch_triage

    try:
        payload = await get_batch_triage(
            BatchTriageRequestWithStatus(alert_ids=alert_ids),
            current_user=current_user, session=session,
        )
    except Exception:
        logger.exception("Alert queue fragment could not read the triage batch")
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("triage"), dict):
        return None
    return payload["triage"]


def _known_systems(session: Session) -> Optional[list]:
    from ion.services.system_resolver_service import list_known_systems

    try:
        found = list_known_systems(session)
    except Exception:
        logger.exception("Alert queue fragment could not list the known systems")
        return None
    return found if isinstance(found, list) else None


@router.get(
    "/alerts/queue",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(QUEUE_PERMISSION))],
)
async def alerts_queue_fragment(
    request: Request,
    time_range: str = Query("24", description="The alert-time-range control's value"),
    custom_from: str = Query("", description="datetime-local start, for a custom range"),
    custom_to: str = Query("", description="datetime-local end, for a custom range"),
    tz_offset: str = Query("", description="The viewer's getTimezoneOffset(), minutes"),
    status: str = Query("", description="The alert-status-filter control's value"),
    system: str = Query("", description="The alert-system-filter control's value"),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The alert queue: the fallback rows for #alerts-tbody, and out of
    band the data block the page's pipeline reads, the system select, the
    notice line, and on a failed read the three side lists.

    Calls get_es_alerts, the handler GET /api/elasticsearch/alerts runs,
    with the arguments loadAlerts derived from the same controls, so the
    alert dict has one definition. Then the batch triage handler for the
    rows' triage status and case, as a read.

    The parameters are the raw control values; the derivation the page did
    (hours from the select, ISO bounds from the datetime-local inputs,
    include_closed from the status filter) is queue_window and
    include_closed, so a saved view that restores the controls and a hand
    change of them take the same path.

    Four outcomes, in queue_outcome. The failed one renders a row that
    names the reason and swaps the side lists to "could not be read" with
    their badges unknown; the data block then says no data was read, so
    the page leaves its arrays alone. The other three carry the array.
    """
    from ion.web import elasticsearch_api as es_api

    window = queue_window(time_range, custom_from, custom_to, tz_offset)
    closed = include_closed(status)
    try:
        payload = await es_api.get_es_alerts(
            hours=window["hours"],
            limit=QUEUE_LIMIT,
            include_closed=closed,
            time_from=window["time_from"],
            time_to=window["time_to"],
            system=system or None,
            current_user=current_user,
            session=session,
        )
        outcome = queue_outcome(payload)
    except Exception:
        logger.exception("Alert queue fragment could not read alerts")
        outcome = {"failed": True, "degraded": False, "reason": None,
                   "connection_error": False, "alerts": None, "arkime_enabled": False}

    alerts = outcome["alerts"]
    triage: Optional[dict] = None
    if alerts:
        triage = await _triage_map([a.get("id") for a in alerts if a.get("id") is not None],
                                   current_user, session)

    view = {
        **outcome,
        "rows": queue_rows(alerts, triage, outcome["arkime_enabled"]) if alerts is not None else None,
        "triage_failed": alerts is not None and len(alerts) > 0 and triage is None,
        "total": len(alerts) if alerts is not None else None,
        "limit": QUEUE_LIMIT,
        "truncated": alerts is not None and len(alerts) >= QUEUE_LIMIT,
        "window": window,
        "include_closed": closed,
        "systems": system_options(alerts, _known_systems(session), system),
        "system": system,
        "colspan": QUEUE_FALLBACK_COLUMNS,
        "can_triage": _can(current_user, TRIAGE_PERMISSION),
        "can_create_case": _can(current_user, CREATE_PERMISSION),
        # The spine. Only the keys the page reads; the rows above carry
        # everything else the fallback needs.
        "data": {"alerts": alerts, "arkime_enabled": outcome["arkime_enabled"]}
                if alerts is not None else None,
    }
    return render_view(request, QUEUE_FRAGMENT, view)


# ---------------------------------------------------------------------------
# The alert detail modal: triage bar, comments, case tab, KFP banner, OpenCTI
# ---------------------------------------------------------------------------
#
# Stage 5. What the ten writers did, measured against the tree before it:
#
#   * `loadTriage` returned on `!response.ok`, so a failed read left the bar
#     saying "Loading triage..." for the life of the modal, and wrote
#     `data.comments || []`, so a payload without a comment list said "No
#     comments yet". When the triage carried no case it wrote the "Not
#     linked" sentence itself; when the read failed it wrote nothing, so the
#     case tab kept whatever the previous alert had left there.
#
#   * `renderTriageBar` offered the status and priority selects, the three
#     closure buttons, Save, Add and Remove on observables and techniques,
#     Create Case and Link to Case to every reader. All of those PUT or POST
#     routes carrying alert:triage or case:create; the page is gated on
#     alert:read.
#
#   * `renderCommentsTab` put comment prose through marked plus DOMPurify on
#     the client. ION has no server-side sanitiser and none is being added
#     (ui/template_render.py records the decision), so comments ship as
#     escaped text with their line breaks kept. Markdown formatting is lost;
#     stored XSS is not reintroduced.
#
#   * `renderCaseTab` wrote `c.notes || []`, `c.severity || '-'`,
#     `c.assigned_to || 'Unassigned'` and `c.closed_by || 'unknown'`, and
#     offered Close Case As, the per-alert closure buttons and Add Note to
#     every reader. It also called checkKFPMatchesForTab, a second round
#     trip for data the server already had in hand.
#
#   * `checkKFPMatches` and `checkKFPMatchesForTab` returned on `!resp.ok`
#     and on `!data.matches`, so a refusal, a malformed answer and "no known
#     false positive matches" all rendered nothing. The banner is the one
#     place this page tells an analyst a case is probably noise; a failed
#     check looked exactly like a clean one. Both built data-args by string
#     concatenation.
#
#   * `enrichObservables` wrote `data.results || []` and
#     `renderEnrichResults` said "No results returned." for it, so a 503 body
#     without a list, a malformed answer and an empty answer were one
#     sentence. Its two button-label writes were a loading state that a CSS
#     rule on .htmx-request now paints.
#
#   * `translateComment` wrote `el.dataset.renderedHtml` back with innerHTML
#     to toggle to the original. The original is text now, so the toggle is
#     textContent.
#
# Three permissions beyond alert:read decide what is offered, each read off
# the live route table rather than guessed: alert:triage for every triage
# mutation, the comment POST, the closure endpoints and close-as-fp;
# case:create for Create Case; case:read for the case tab, which is GET
# /api/cases/{id}. A viewer with alert:read and not case:read gets a case
# tab that says the case is withheld and names the permission, a fourth
# outcome beside unlinked, failed and read.
#
# The triage dict the page's mutation functions still need (addObservable,
# removeObservable, aiSuggestMitre and the closure form all read
# triageCache[alertId]) rides inside the bar in an application/json block,
# which the page copies into its cache after the swap. Same transitional
# shape as the queue's data block, for the same reason: the mutations stay
# on fetch because their routes take JSON bodies.

TRIAGE_BAR_FRAGMENT = "_fragments/alerts_triage_bar.html"
COMMENTS_FRAGMENT = "_fragments/alerts_comments.html"
CASE_TAB_FRAGMENT = "_fragments/alerts_case_tab.html"
KFP_BANNER_FRAGMENT = "_fragments/alerts_kfp_banner.html"
ENRICH_FRAGMENT = "_fragments/alerts_enrich.html"

#: What GET /api/elasticsearch/alerts/{id}/triage, POST
#: /api/known-false-positives/match and POST /api/translator/translate carry.
#: POST /api/opencti/enrich/batch is auth-only, but the observables it is
#: given come from the triage read, so the enrich fragment is gated on this
#: too: the stricter of the two reads it folds together.
DETAIL_PERMISSION = "alert:read"

#: The page's TRIAGE_STATUSES, PRIORITIES and OBSERVABLE_TYPES, and the
#: tactic list its MITRE add row offered.
TRIAGE_STATUSES = ("open", "acknowledged", "closed")
PRIORITIES = ("critical", "high", "medium", "low")
OBSERVABLE_TYPES = ("hostname", "source_ip", "destination_ip", "url", "domain", "user_account",
                    "ipv4", "ipv6", "email", "sha256", "sha1", "md5", "filename", "mac", "cve")
MITRE_TACTICS = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
)

#: ION observable type to the OpenCTI type enrichObservables sent. None
#: means not enrichable; a type absent from the map is sent as itself, which
#: is what the page did (`typeMap[obs.type] !== undefined ? ... : obs.type`).
OPENCTI_TYPE_MAP: dict[str, Optional[str]] = {
    "source_ip": "ipv4-addr",
    "destination_ip": "ipv4-addr",
    "hostname": "domain-name",
    "domain": "domain-name",
    "url": "url",
    "user_account": None,
}

#: Bob confidence thresholds, from the page: 80 and over is High, 60 and
#: over Medium, anything else Low. A measured 0 is Low, not absent.
BOB_HIGH = 80
BOB_MEDIUM = 60

#: The bob_escalation_badge value that means the circuit breaker fired.
BOB_LOW_CONFIDENCE = "low_confidence_triage"

#: Observable types whose values the KFP check matches as IPs, as
#: checkKFPMatches filtered them.
KFP_IP_TYPES = ("source_ip", "destination_ip")


def triage_outcome(payload: Any) -> dict:
    """The triage read as failed, or as a triage (dict or None for no
    record) plus a comment list (or None when the payload carried no list).

    A payload that is not a dict, or whose `triage` is neither a dict nor
    None, is a failed read: the handler did not produce what it promises.
    `comments` is read separately so a payload with a triage and no comment
    list renders the bar and says the comments could not be read, rather
    than "No comments yet".
    """
    if not isinstance(payload, dict):
        return {"failed": True, "triage": None, "comments": None}
    triage = payload.get("triage")
    if triage is not None and not isinstance(triage, dict):
        return {"failed": True, "triage": None, "comments": None}
    return {"failed": False, "triage": triage, "comments": _rows(payload, "comments")}


def mitre_rows(saved: Any, alert_mitre: dict) -> list:
    """The saved techniques with the alert's own auto-detected one put first
    when none of them already names it, as renderTriageBar merged them.
    `index` is the position in the SAVED list, which is what
    removeMitreTechnique splices, so the auto row has none."""
    out = []
    for idx, t in enumerate(saved if isinstance(saved, list) else []):
        if not isinstance(t, dict):
            continue
        out.append({"index": idx, "technique_id": t.get("technique_id"),
                    "technique_name": t.get("technique_name"),
                    "auto": t.get("source") == "auto"})
    auto_id = alert_mitre.get("technique_id")
    if auto_id and not any(r["technique_id"] == auto_id for r in out):
        out.insert(0, {"index": None, "technique_id": auto_id,
                       "technique_name": alert_mitre.get("technique_name") or "",
                       "auto": True})
    return out


def bob_badge(confidence: Any, verdict: Any, escalation: Any) -> Optional[dict]:
    """The Bob confidence pill and the auto-escalated pill, or None when
    there is neither. `confidence` is an int or None; 0 is a measured Low."""
    conf = _count(confidence)
    escalated = escalation == BOB_LOW_CONFIDENCE
    if conf is None and not escalated:
        return None
    level = None
    if conf is not None:
        level = "high" if conf >= BOB_HIGH else "medium" if conf >= BOB_MEDIUM else "low"
    verdict_text = str(plain(verdict)).replace("_", " ") if verdict else None
    return {"confidence": conf, "level": level, "verdict": verdict_text, "escalated": escalated}


def observable_rows(observables: Any, enrichment: Optional[dict] = None) -> list:
    """The triage's observables with the derivations the list needs.

    Every element keeps its position, including one that is not a dict,
    because `index` is what removeObservable splices out of the stored
    list; dropping a malformed row would make Remove delete its neighbour.
    `found` is True, False or None: None when no enrichment was run or the
    value was not in its results, so the dot is not drawn.
    """
    out = []
    for idx, o in enumerate(observables if isinstance(observables, list) else []):
        if isinstance(o, dict):
            otype = str(o.get("type") or "")
            value = str(o.get("value") or "")
        else:
            otype, value = "", str(o)
        found = enrichment.get(value) if isinstance(enrichment, dict) else None
        out.append({"index": idx, "type": otype, "type_label": otype.replace("_", " "),
                    "value": value, "found": found if isinstance(found, bool) else None})
    return out


def enrichable_observables(observables: Any) -> list:
    """What enrichObservables sent: each observable mapped through
    OPENCTI_TYPE_MAP, the unmappable dropped, the original type kept for
    the result rows."""
    out = []
    for o in observables if isinstance(observables, list) else []:
        if not isinstance(o, dict):
            continue
        otype = o.get("type")
        mapped = OPENCTI_TYPE_MAP.get(otype, otype) if otype in OPENCTI_TYPE_MAP else otype
        if not mapped or not o.get("value"):
            continue
        out.append({"type": mapped, "value": o.get("value"), "original_type": otype})
    return out


def triage_view(triage: Optional[dict], alert_mitre: dict) -> dict:
    """What the bar renders, derived from the handler's triage dict or from
    no record at all. No record is status open with nothing else, which is
    what the page showed and what an alert that nobody has touched is."""
    t = triage if isinstance(triage, dict) else {}
    observables = t.get("observables")
    observables = observables if isinstance(observables, list) else []
    return {
        "exists": triage is not None,
        "status": plain(t.get("status")) if triage is not None else "open",
        "priority": t.get("priority") or "",
        "case_id": t.get("case_id"),
        "case_number": t.get("case_number"),
        "analyst_notes": t.get("analyst_notes") or "",
        "observables": observable_rows(observables),
        "observable_count": len(observables),
        "enrichable": bool(enrichable_observables(observables)),
        "mitre": mitre_rows(t.get("mitre_techniques"), alert_mitre),
        "bob": bob_badge(t.get("suggested_verdict_confidence_int"), t.get("suggested_verdict"),
                         t.get("bob_escalation_badge")),
    }


def comment_rows(comments: list) -> list:
    return [
        {"id": c.get("id"), "user": c.get("user"), "content": c.get("content") or "",
         "created_at": c.get("created_at")}
        for c in comments if isinstance(c, dict)
    ]


def kfp_criteria(case: dict) -> dict:
    """hosts, users, rules and ips, as checkKFPMatches gathered them: the
    three list columns and the values of source_ip and destination_ip
    observables."""
    def strings(value: Any) -> list:
        return [str(v) for v in value if v] if isinstance(value, list) else []

    observables = case.get("observables")
    ips = [
        str(o.get("value")) for o in (observables if isinstance(observables, list) else [])
        if isinstance(o, dict) and o.get("type") in KFP_IP_TYPES and o.get("value")
    ]
    return {"hosts": strings(case.get("affected_hosts")), "users": strings(case.get("affected_users")),
            "rules": strings(case.get("triggered_rules")), "ips": ips}


def kfp_check(session: Session, case: dict) -> dict:
    """The known-false-positive check for a case, as one of four outcomes.

      skipped  the case is closed, or has nothing to match on. The page
               returned before asking in both cases.
      failed   the match raised. The page returned on !resp.ok and rendered
               nothing, so a failed check and a clean case were one picture.
      match    the first match, as the page showed only the first.
      none     the check ran and nothing matched.

    Calls _match_known_false_positives, the function POST
    /api/known-false-positives/match calls, with the same four lists.
    """
    from ion.web.api import _match_known_false_positives

    # `reason` on a skip, because "closed" and "nothing to match on" are two
    # facts and the banner words them differently. The page returned early
    # for both and said nothing either way, so they were one picture; the
    # second one is the case where an analyst could otherwise assume the
    # check ran and came back clean.
    if plain(case.get("status")) == "closed":
        return {"skipped": True, "reason": "closed", "failed": False,
                "match": None, "total": None}
    criteria = kfp_criteria(case)
    if not any(criteria.values()):
        return {"skipped": True, "reason": "nothing-to-match", "failed": False,
                "match": None, "total": None}
    try:
        matches = _match_known_false_positives(session, **criteria)
    except Exception:
        logger.exception("KFP check could not run for case %s", case.get("id"))
        return {"skipped": False, "reason": None, "failed": True,
                "match": None, "total": None}
    if not isinstance(matches, list):
        return {"skipped": False, "reason": None, "failed": True,
                "match": None, "total": None}
    found = [m for m in matches if isinstance(m, dict)]
    first = found[0] if found else None
    if first is not None:
        fields = first.get("matched_fields")
        first = {**first, "matched_fields": [str(f) for f in fields] if isinstance(fields, list) else []}
    return {"skipped": False, "reason": None, "failed": False,
            "match": first, "total": len(found)}


def case_tab_view(case: dict) -> dict:
    """What the case tab renders beyond _case_view: the context tag groups,
    the closure block, the linked alert rows and the observable rows with
    their enrichment, as renderCaseTab and renderCaseObservables derived
    them."""
    view = _case_view(case)
    groups = []
    for key, label, cls in (("affected_hosts", "Hosts", "tag-host"),
                            ("affected_users", "Users", "tag-user"),
                            ("triggered_rules", "Rules", "tag-rule")):
        items = case.get(key)
        if isinstance(items, list) and items:
            groups.append({"label": label, "cls": cls, "items": [str(i) for i in items]})
    alerts = []
    for a in view["alerts"]:
        if not isinstance(a, dict):
            continue
        alerts.append({"es_alert_id": a.get("es_alert_id"), "status": plain(a.get("status")),
                       "priority": a.get("priority")})
    observables = []
    for o in view["observables"]:
        if not isinstance(o, dict):
            continue
        enrichment = o.get("enrichment") if isinstance(o.get("enrichment"), dict) else None
        level = o.get("threat_level") or (enrichment or {}).get("threat_level") or "unknown"
        actors = (enrichment or {}).get("threat_actors")
        names = [str(ta.get("name") if isinstance(ta, dict) else ta) for ta in actors] \
            if isinstance(actors, list) and actors else []
        otype = str(o.get("type") or "")
        observables.append({
            "type": otype, "type_label": otype.replace("_", " "), "value": str(o.get("value") or ""),
            "threat_level": str(level), "enriched": bool(enrichment or o.get("observable_id")),
            "malicious": bool(enrichment and enrichment.get("is_malicious")),
            "score": enrichment.get("score") if enrichment else None,
            "actors": names,
        })
    return {
        **view,
        "closed": view["status"] == "closed",
        "groups": groups,
        "alert_rows": alerts,
        "observable_rows": observables,
    }


def enrich_outcome(result: Any) -> dict:
    """What the enrich handler answered, as unavailable (it returned a
    JSONResponse, which is how it says 503 with an `error`), failed (no
    list under `results`), or the list."""
    from fastapi.responses import JSONResponse

    if isinstance(result, JSONResponse):
        import json

        try:
            body = json.loads(result.body)
        except Exception:
            body = {}
        error = body.get("error") if isinstance(body, dict) else None
        return {"unavailable": str(error) if error else f"OpenCTI answered HTTP {result.status_code}",
                "failed": False, "results": None}
    results = _rows(result, "results")
    if results is None:
        return {"unavailable": None, "failed": True, "results": None}
    return {"unavailable": None, "failed": False, "results": [r for r in results if isinstance(r, dict)]}


def enrich_rows(results: list, enrichable: list) -> list:
    """The result rows as renderEnrichResults derived them, each score
    guarded with `is not none` so a score of 0 renders."""
    out = []
    for idx, r in enumerate(results):
        original = enrichable[idx]["original_type"] if idx < len(enrichable) else r.get("type")
        original = str(original or "")
        labels = []
        for lbl in r.get("labels") if isinstance(r.get("labels"), list) else []:
            if not isinstance(lbl, dict):
                continue
            color = lbl.get("color")
            style = (f"background:{color}22; color:{color}" if color
                     else "background:rgba(139,92,246,0.1); color:#8b5cf6")
            labels.append({"value": lbl.get("value"), "style": style})
        actors = [{"name": ta.get("name"), "description": ta.get("description") or ""}
                  for ta in (r.get("threat_actors") if isinstance(r.get("threat_actors"), list) else [])
                  if isinstance(ta, dict)]
        indicators = [{"name": ind.get("name"), "description": ind.get("description"),
                       "score": ind.get("score")}
                      for ind in (r.get("indicators") if isinstance(r.get("indicators"), list) else [])
                      if isinstance(ind, dict)]
        observable = r.get("observable") if isinstance(r.get("observable"), dict) else None
        out.append({
            "found": r.get("found") is True,
            "type": original, "type_label": original.replace("_", " "),
            "value": str(r.get("value") or ""),
            "labels": labels, "actors": actors, "indicators": indicators,
            "observable_score": observable.get("score") if observable else None,
            "error": r.get("error"),
        })
    return out


def enrichment_map(results: list) -> dict:
    """value to found, for the dots on the observables list."""
    return {str(r.get("value")): r.get("found") is True for r in results if isinstance(r, dict)}


async def _read_triage(alert_id: str, current_user: User, session: Session) -> dict:
    """triage_outcome over the handler GET .../triage runs, or failed."""
    from ion.web.api import get_alert_triage

    try:
        payload = await get_alert_triage(alert_id, current_user=current_user, session=session)
    except Exception:
        logger.exception("Triage could not be read for alert %s", alert_id)
        return {"failed": True, "triage": None, "comments": None}
    return triage_outcome(payload)


async def _case_tab(case_id: int, current_user: User, session: Session, flags: dict,
                    ai_available: bool) -> dict:
    """The case tab's context for one case: missing, failed, or the case
    with its view, its KFP check and the controls the viewer may use."""
    base = {"case_id": case_id, "ai_available": ai_available, **flags}
    try:
        case = await _read_case(case_id, current_user, session)
    except HTTPException as exc:
        if exc.status_code == 404:
            return {**base, "missing": True, "failed": False, "case": None, "view": None,
                    "kfp": None, "can_close": False}
        logger.exception("Case tab refused for case %s", case_id)
        return {**base, "missing": False, "failed": True, "case": None, "view": None,
                "kfp": None, "can_close": False}
    except Exception:
        logger.exception("Case tab could not read case %s", case_id)
        return {**base, "missing": False, "failed": True, "case": None, "view": None,
                "kfp": None, "can_close": False}
    view = case_tab_view(case)
    return {
        **base, "missing": False, "failed": False, "case": case, "view": view,
        "kfp": kfp_check(session, case),
        # closeCaseWithAlerts closes the first linked alert (alert:triage) and
        # the backend closes the rest and the case; with no alerts it PATCHes
        # the case (case:update). Stage 2's rule, repeated here.
        "can_close": flags["can_triage"] if view["alerts"] else flags["can_update"],
    }


def _detail_flags(user: Optional[User]) -> dict:
    return {
        "can_triage": _can(user, TRIAGE_PERMISSION),
        "can_create_case": _can(user, CREATE_PERMISSION),
        "can_read_case": _can(user, PERMISSION),
        "can_update": _can(user, UPDATE_PERMISSION),
        "can_read_playbooks": _can(user, PLAYBOOK_READ_PERMISSION),
    }


@router.get(
    "/alerts/triage/{alert_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(DETAIL_PERMISSION))],
)
async def alerts_triage_fragment(
    request: Request,
    alert_id: str,
    mitre_technique_id: str = Query("", description="The alert's own technique id, from the row"),
    mitre_technique_name: str = Query(""),
    mitre_tactic_name: str = Query(""),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The triage bar, and out of band the comments tab and the case tab,
    from one call to the handler GET .../triage runs.

    The alert's own MITRE technique is client state (the row the analyst
    clicked), passed as parameters so the auto badge can be merged here as
    renderTriageBar merged it.

    Outcomes. The triage read: failed, no record, record. The comments:
    not read (the payload had no list), none, rows. The case tab: not read
    (the triage read failed), unlinked, withheld (no case:read), missing,
    failed, read. The page had one render for the first of each.
    """
    flags = _detail_flags(current_user)
    alert_mitre = {"technique_id": mitre_technique_id or None,
                   "technique_name": mitre_technique_name or None,
                   "tactic_name": mitre_tactic_name or None}
    read = await _read_triage(alert_id, current_user, session)
    ai_available = await _ai_available()

    view = None if read["failed"] else triage_view(read["triage"], alert_mitre)
    case_tab: Optional[dict] = None
    if read["failed"]:
        case_link = "unread"
    elif view is None or view["case_id"] is None:
        case_link = "none"
    elif not flags["can_read_case"]:
        case_link = "withheld"
    else:
        case_link = "read"
        case_tab = await _case_tab(int(view["case_id"]), current_user, session, flags, ai_available)

    view = {
        "alert_id": alert_id,
        "failed": read["failed"],
        "triage": read["triage"],
        "view": view,
        "comments": comment_rows(read["comments"]) if read["comments"] is not None else None,
        "comments_failed": read["comments"] is None,
        "case_link": case_link,
        "case_tab": case_tab,
        "ai_available": ai_available,
        "statuses": TRIAGE_STATUSES,
        "priorities": PRIORITIES,
        "observable_types": OBSERVABLE_TYPES,
        "tactics": MITRE_TACTICS,
        "case_read_permission": PERMISSION,
        **flags,
    }
    return render_view(request, TRIAGE_BAR_FRAGMENT, view)


@router.get(
    "/alerts/comments/{alert_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(DETAIL_PERMISSION))],
)
async def alerts_comments_fragment(
    request: Request,
    alert_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The comments tab alone, for the page's renderCommentsTab, which the
    shared detail module calls and addComment calls after posting. The bar
    is not re-rendered, so an analyst's unsaved notes stay in the box."""
    read = await _read_triage(alert_id, current_user, session)
    view = {
        "alert_id": alert_id,
        "comments": comment_rows(read["comments"]) if read["comments"] is not None else None,
        "comments_failed": read["comments"] is None,
        "can_triage": _can(current_user, TRIAGE_PERMISSION),
    }
    return render_view(request, COMMENTS_FRAGMENT, view)


@router.get(
    "/alerts/case-tab/{case_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION)),
                  Depends(require_permission(DETAIL_PERMISSION))],
)
async def alerts_case_tab_fragment(
    request: Request,
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The case tab alone, for renderCaseTab's callers after a mutation.

    Two guards: case:read for GET /api/cases/{id}, and alert:read for the
    KFP match the tab runs inline, which POST
    /api/known-false-positives/match carries.
    """
    flags = _detail_flags(current_user)
    ctx = await _case_tab(case_id, current_user, session, flags, await _ai_available())
    view = ctx
    return render_view(request, CASE_TAB_FRAGMENT, view)


@router.get(
    "/alerts/kfp-banner/{case_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(PERMISSION)),
                  Depends(require_permission(DETAIL_PERMISSION))],
)
async def alerts_kfp_banner_fragment(
    request: Request,
    case_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The known-false-positive banner for the case management modal.

    Reads the case through GET /api/cases/{id}'s handler and runs the match
    the JSON endpoint runs. Close as Known FP is offered only with
    alert:triage, which POST /api/cases/{id}/close-as-fp carries.
    """
    can_triage = _can(current_user, TRIAGE_PERMISSION)

    def answer(ctx: dict) -> Response:
        view = {"case_id": case_id, "can_triage": can_triage, **ctx}
        return render_view(request, KFP_BANNER_FRAGMENT, view)

    try:
        case = await _read_case(case_id, current_user, session)
    except HTTPException as exc:
        if exc.status_code == 404:
            return answer({"missing": True, "kfp": None})
        logger.exception("KFP banner refused for case %s", case_id)
        return answer({"missing": False, "kfp": {"skipped": False, "reason": None,
                                                 "failed": True, "match": None, "total": None}})
    except Exception:
        logger.exception("KFP banner could not read case %s", case_id)
        return answer({"missing": False, "kfp": {"skipped": False, "reason": None,
                                                 "failed": True, "match": None, "total": None}})
    return answer({"missing": False, "kfp": kfp_check(session, case)})


@router.get(
    "/alerts/enrich/{alert_id}",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(DETAIL_PERMISSION))],
)
async def alerts_enrich_fragment(
    request: Request,
    alert_id: str,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """OpenCTI enrichment of the alert's triage observables, into
    #enrich-results, with the observables list re-rendered out of band so
    each row carries its found or not-found dot.

    The observables are read off the AlertTriage row directly, the column
    GET .../triage emits as `observables`; calling that handler here would
    write a second alert_view audit event and re-run its memory lookups
    for a list already in hand. Then the handler POST /api/opencti/enrich/batch
    runs, with the same mapped list enrichObservables sent.

    Outcomes: no triage record or no observables; none enrichable;
    OpenCTI unavailable (the handler's 503, with its reason); failed; an
    answer with no results; results. The page folded the last four into
    "No results returned." and a catch.
    """
    from ion.models.alert_triage import AlertTriage
    from ion.web.api import OpenCTIEnrichBatchRequest, enrich_batch

    can_triage = _can(current_user, TRIAGE_PERMISSION)

    def answer(ctx: dict) -> Response:
        view = {"alert_id": alert_id, "can_triage": can_triage,
                 "no_observables": False, "enrichable": None, "unavailable": None,
                 "failed": False, "results": None, "observables": None,
                 "found_count": None, "ai_available": False, **ctx}
        return render_view(request, ENRICH_FRAGMENT, view)

    try:
        triage = session.query(AlertTriage).filter_by(es_alert_id=alert_id).first()
    except Exception:
        logger.exception("Enrich fragment could not read the triage for alert %s", alert_id)
        return answer({"failed": True})
    observables = triage.observables if triage is not None and isinstance(triage.observables, list) else []
    if not observables:
        return answer({"no_observables": True})
    enrichable = enrichable_observables(observables)
    if not enrichable:
        return answer({"enrichable": []})

    try:
        result = await enrich_batch(
            OpenCTIEnrichBatchRequest(observables=[{"type": e["type"], "value": e["value"]} for e in enrichable]),
            current_user=current_user,
        )
        outcome = enrich_outcome(result)
    except Exception:
        logger.exception("Enrich fragment failed for alert %s", alert_id)
        return answer({"enrichable": enrichable, "failed": True})
    if outcome["results"] is None:
        return answer({"enrichable": enrichable, "unavailable": outcome["unavailable"],
                       "failed": outcome["failed"]})
    results = outcome["results"]
    return answer({
        "enrichable": enrichable,
        "results": enrich_rows(results, enrichable),
        "found_count": sum(1 for r in results if r.get("found") is True),
        "observables": observable_rows(observables, enrichment_map(results)),
        "ai_available": await _ai_available(),
    })


# ---------------------------------------------------------------------------
# The analytics drawer: key metrics, the trend chart, two donuts and the
# three top-N bar lists
# ---------------------------------------------------------------------------
#
# Stage 6. These all aggregated `allAlerts`, the array loadAlerts filled, and
# renderAnalytics is not called from applyFilters, so the drawer reflects the
# fetched set rather than the reader's narrowing. That is why this route
# takes the same six control values the queue takes and does the same read
# through the same helpers: one definition of the window, one definition of
# which alerts are in it, and no second filter to disagree with the queue.
#
# What the writers did, measured against the tree before this stage:
#
#   * renderTrendChart opened with
#
#         if (!container || allAlerts.length === 0) {
#             container.innerHTML = '<div class="empty-state">No data</div>';
#
#     which dereferences `container` on the branch that tests it for null.
#     It never fired because the container is in the shell, but the guard is
#     backwards and is not carried over.
#
#   * Every one of the five said "No data" for an empty set, and `allAlerts`
#     stays empty after a failed read, so a window with no alerts in it and
#     a window nobody could read were one picture in every chart at once.
#     That is the whole drawer agreeing on a wrong answer.
#
#   * The trend chart's x-axis labels came from toLocaleTimeString, so the
#     buckets were computed as absolute instants and then labelled on the
#     reader's clock. Two analysts in different zones read different hours
#     off the same bars. The labels are UTC now and the axis says so.
#
#   * renderTopCountries read `a.raw_data.source?.geo` and counted
#     `geo.country_name || geo.country_iso_code`, so an alert whose geo
#     block carries neither was skipped silently rather than counted as
#     unattributed.
#
# The donut geometry is reproduced rather than borrowed from cases.py, which
# grew a `donut()` of its own. That one draws with stroke-dasharray on a
# circle and this one draws path arcs, and the port is meant to be invisible,
# so the arcs are the ones that were on screen.

#: `.slice(0, 7)` in all three bar lists.
ANALYTICS_TOP_N = 7

#: The severity donut's buckets, in the order the page listed them. The
#: colours used to live here too, as a tuple travelling into every arc of
#: the view model. They are in frontend/ion-pages.css now, keyed by these names,
#: for the reason tide_band's band moved: which colour paints "critical"
#: is this stylesheet's answer, and a model that carries it makes every
#: reader of /ui/alerts/analytics inherit ION's palette.
SEVERITY_SLICES = (("Critical", "critical"), ("High", "high"),
                   ("Medium", "medium"), ("Low", "low"), ("Info", "info"))

#: The triage donut's, likewise.
TRIAGE_SLICES = (("Open", "open"), ("Acknowledged", "acknowledged"),
                 ("Closed", "closed"))

#: The donut's geometry, from the page: cx 70, r 58, inner 34, h 190.
DONUT_W, DONUT_H = 200, 190
DONUT_CX, DONUT_R, DONUT_INNER = 70, 58, 34
DONUT_LEGEND_X = 145

#: The trend chart's, from the page.
TREND_W, TREND_H = 600, 180


def _bucket_plan(hours: int) -> dict:
    """Bucket width, count and label format for a window, as the page's
    four-way branch chose them. The label is a strftime pattern rather than
    a closure, because it is applied on the server and in UTC."""
    if hours <= 1:
        return {"ms": 5 * 60, "count": 12, "fmt": "%H:%M"}
    if hours <= 24:
        return {"ms": 60 * 60, "count": 24, "fmt": "%H:%M"}
    if hours <= 168:
        return {"ms": 6 * 60 * 60, "count": -(-hours // 6), "fmt": "%d %b %H"}
    return {"ms": 24 * 60 * 60, "count": -(-hours // 24), "fmt": "%d %b"}


def trend_buckets(alerts: list, hours: int, now: Optional[datetime] = None) -> dict:
    """The trend chart's bars: one per bucket, each with its total and its
    critical and high counts, plus the labels for the axis.

    `count` is a measured zero for a bucket nothing landed in, which is the
    point of a trend chart and is not the same as the window being
    unreadable.
    """
    now = now or datetime.now(timezone.utc)
    plan = _bucket_plan(hours)
    start = now - timedelta(hours=hours)
    buckets = [
        {"start": start + timedelta(seconds=i * plan["ms"]),
         "count": 0, "critical": 0, "high": 0}
        for i in range(plan["count"])
    ]
    for a in alerts if isinstance(alerts, list) else []:
        if not isinstance(a, dict):
            continue
        when = _parse_instant(a.get("timestamp") or a.get("@timestamp"))
        if when is None:
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        index = int((when - start).total_seconds() // plan["ms"])
        if 0 <= index < len(buckets):
            buckets[index]["count"] += 1
            severity = str(plain(a.get("severity")) or "")
            if severity == "critical":
                buckets[index]["critical"] += 1
            elif severity == "high":
                buckets[index]["high"] += 1
    peak = max((b["count"] for b in buckets), default=0)
    every = max(1, -(-len(buckets) // 6))
    for i, b in enumerate(buckets):
        b["label"] = b["start"].strftime(plan["fmt"]) if i % every == 0 else None
        b["pct"] = round(b["count"] / peak * 100, 2) if peak else 0.0
        b["iso"] = b["start"].isoformat().replace("+00:00", "Z")
    return {"buckets": buckets, "peak": peak, "total": sum(b["count"] for b in buckets)}


def top_counts(alerts: list, field: str, limit: int = ANALYTICS_TOP_N) -> list:
    """The top `limit` values of one field, with the share of the largest so
    the bar widths need no arithmetic in the template."""
    counts: dict = {}
    for a in alerts if isinstance(alerts, list) else []:
        if not isinstance(a, dict):
            continue
        value = a.get(field)
        if value in (None, ""):
            continue
        key = str(value)
        counts[key] = counts.get(key, 0) + 1
    rows = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    peak = rows[0][1] if rows else 0
    return [{"name": name, "count": count,
             "pct": round(count / peak * 100) if peak else 0}
            for name, count in rows]


def country_counts(alerts: list, limit: int = ANALYTICS_TOP_N) -> dict:
    """Alerts by source country, plus how many carried a geo block with no
    country in it. The page skipped those silently, so a window of alerts
    that were all geolocated to nowhere read as a window with no geo data
    at all.
    """
    counts: dict = {}
    unattributed = 0
    for a in alerts if isinstance(alerts, list) else []:
        if not isinstance(a, dict):
            continue
        raw = a.get("raw_data")
        source = raw.get("source") if isinstance(raw, dict) else None
        geo = source.get("geo") if isinstance(source, dict) else None
        if not isinstance(geo, dict):
            continue
        name = geo.get("country_name") or geo.get("country_iso_code")
        if not name:
            unattributed += 1
            continue
        key = str(name)
        counts[key] = counts.get(key, 0) + 1
    rows = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    peak = rows[0][1] if rows else 0
    return {
        "rows": [{"name": name, "count": count,
                  "pct": round(count / peak * 100) if peak else 0,
                  "hue": 200 + i * 25}
                 for i, (name, count) in enumerate(rows)],
        "unattributed": unattributed,
    }


def donut_arcs(slices: list) -> Optional[dict]:
    """The path arcs and legend for a donut, or None when there is nothing
    to draw from.

    Three outcomes, as the cases donut has: None in means the source could
    not be read and None comes out. A total of zero is a measurement, every
    slice counted and every count zero, and renders as an empty ring rather
    than as "No data", which the page could not tell from a failed read.
    """
    if slices is None:
        return None
    total = sum(s["value"] for s in slices)
    arcs, legend = [], []
    angle = -math.pi / 2
    for s in slices:
        if s["value"]:
            share = s["value"] / total
            sweep = share * 2 * math.pi
            large = 1 if sweep > math.pi else 0
            cy = DONUT_H / 2
            x1 = DONUT_CX + DONUT_R * math.cos(angle)
            y1 = cy + DONUT_R * math.sin(angle)
            x2 = DONUT_CX + DONUT_R * math.cos(angle + sweep)
            y2 = cy + DONUT_R * math.sin(angle + sweep)
            ix1 = DONUT_CX + DONUT_INNER * math.cos(angle)
            iy1 = cy + DONUT_INNER * math.sin(angle)
            ix2 = DONUT_CX + DONUT_INNER * math.cos(angle + sweep)
            iy2 = cy + DONUT_INNER * math.sin(angle + sweep)
            arcs.append({
                "key": s["key"],
                "d": (f"M{x1:.2f},{y1:.2f} A{DONUT_R},{DONUT_R} 0 {large},1 "
                      f"{x2:.2f},{y2:.2f} L{ix2:.2f},{iy2:.2f} "
                      f"A{DONUT_INNER},{DONUT_INNER} 0 {large},0 {ix1:.2f},{iy1:.2f} Z"),
                "label": s["label"], "value": s["value"],
                "pct": round(s["value"] / total * 100),
            })
            legend.append({"key": s["key"], "label": s["label"],
                           "value": s["value"],
                           "pct": round(s["value"] / total * 100),
                           "y": 16 + len(legend) * 18})
            angle += sweep
    return {"total": total, "arcs": arcs, "legend": legend,
            "cy": DONUT_H / 2, "w": DONUT_W, "h": DONUT_H,
            "cx": DONUT_CX, "r": DONUT_R, "inner": DONUT_INNER,
            "legend_x": DONUT_LEGEND_X}


def _slice_counts(alerts: list, field: str, spec: tuple) -> Optional[list]:
    """Counts for a donut's named buckets, or None when there is no list to
    count. Every named bucket is present with its zero, because the page
    pre-seeded them and a severity nothing arrived under is a measured zero
    rather than a missing category."""
    if not isinstance(alerts, list):
        return None
    counts = {key: 0 for _label, key in spec}
    for a in alerts:
        if not isinstance(a, dict):
            continue
        value = str(plain(a.get(field)) or "")
        if value in counts:
            counts[value] += 1
    return [{"label": label, "key": key, "value": counts[key]}
            for label, key in spec]


def triage_slice_counts(alerts: list, triage: Optional[dict]) -> Optional[list]:
    """The triage donut's three counts, from the batch read rather than from
    the alert rows, which do not carry a triage status.

    `triageCache[a.id]?.status || 'open'` is the rule the page used, so an
    alert with no triage record counts as open: it is an alert nobody has
    triaged, which is what open means here. A batch read that failed is a
    different thing, and None comes back for it so the donut says it was not
    counted instead of reporting every alert as open.
    """
    if not isinstance(alerts, list) or triage is None:
        return None
    counts = {key: 0 for _label, key in TRIAGE_SLICES}
    for a in alerts:
        if not isinstance(a, dict):
            continue
        record = triage.get(str(a.get("id")))
        status = str(plain(record.get("status")) or "") if isinstance(record, dict) else ""
        if not status:
            status = "open"
        if status in counts:
            counts[status] += 1
    return [{"label": label, "key": key, "value": counts[key]}
            for label, key in TRIAGE_SLICES]


@router.get(
    "/alerts/analytics",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(QUEUE_PERMISSION))],
)
async def alerts_analytics_fragment(
    request: Request,
    time_range: str = Query("24"),
    custom_from: str = Query(""),
    custom_to: str = Query(""),
    tz_offset: str = Query(""),
    status: str = Query(""),
    system: str = Query(""),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The analytics drawer, over the same window the queue reads.

    The same six raw control values, through queue_window and
    include_closed, so the drawer and the table cannot disagree about which
    alerts are in the window. The read is the same handler at the same
    limit, which means the drawer is also capped at QUEUE_LIMIT and says so.

    Outcomes: failed, degraded (the read answered with a message and some
    rows), and read. Every chart derives from one list, so a failed read is
    one sentence here rather than the same wrong "No data" in five places.
    """
    from ion.web import elasticsearch_api as es_api

    window = queue_window(time_range, custom_from, custom_to, tz_offset)
    try:
        payload = await es_api.get_es_alerts(
            hours=window["hours"],
            limit=QUEUE_LIMIT,
            include_closed=include_closed(status),
            time_from=window["time_from"],
            time_to=window["time_to"],
            system=system or None,
            current_user=current_user,
            session=session,
        )
        outcome = queue_outcome(payload)
    except Exception:
        logger.exception("Alert analytics fragment could not read alerts")
        outcome = {"failed": True, "degraded": False, "reason": None,
                   "connection_error": False, "alerts": None,
                   "arkime_enabled": False}

    alerts = outcome["alerts"]
    # The triage statuses come from the same batch handler the queue uses,
    # because the alert rows do not carry one. Read as a read: no
    # es_statuses, so its Kibana-to-ION sync does not run.
    triage_map: Optional[dict] = None
    if alerts:
        ids = [str(a.get("id")) for a in alerts if isinstance(a, dict) and a.get("id")]
        triage_map = await _triage_map(ids, current_user, session) if ids else {}
    elif alerts is not None:
        triage_map = {}
    severity = _slice_counts(alerts, "severity", SEVERITY_SLICES)
    triage = triage_slice_counts(alerts, triage_map)
    view = {
        "failed": outcome["failed"],
        "degraded": outcome["degraded"],
        "reason": outcome["reason"],
        "connection_error": outcome["connection_error"],
        # The key metric cards are filled by the page with textContent,
        # not innerHTML, and read triageCache, which is client state. They
        # are not this stage's and nothing is rendered for them here.
        "trend": trend_buckets(alerts, window["hours"]) if alerts is not None else None,
        "hours": window["hours"],
        "defaulted": window["defaulted"],
        "truncated": alerts is not None and len(alerts) >= QUEUE_LIMIT,
        "limit": QUEUE_LIMIT,
        "severity_donut": donut_arcs(severity),
        "triage_donut": donut_arcs(triage),
        "countries": country_counts(alerts) if alerts is not None else None,
        "hosts": top_counts(alerts, "host") if alerts is not None else None,
        "rules": top_counts(alerts, "rule_name") if alerts is not None else None,
        "trend_w": TREND_W,
        "trend_h": TREND_H,
    }
    return render_view(request, ANALYTICS_FRAGMENT, view)


# ---------------------------------------------------------------------------
# The analytics drawer's systems tab
# ---------------------------------------------------------------------------
#
# Stage 7. loadAdSystems fetched GET /api/analytics/system-overview and
# renderAdSystems plus buildAdSysCard assembled the cards.
#
# What they did, measured against the tree before this stage:
#
#   * The fetch sent `Authorization: Bearer ${localStorage.getItem('token')}`.
#     Nothing in this codebase ever calls localStorage.setItem('token', ...),
#     and this was its only reader, so the header was always the string
#     "Bearer null". It worked anyway, because get_session_token tries the
#     ion_session cookie first and only falls back to the header. Had the
#     precedence been the other way round the systems tab would have
#     answered 401 for every user since it was written. The fragment sends
#     no header at all.
#
#   * `data.total_alerts || 0`, `total_systems || 0`, `mapped_systems || 0`
#     and `avg_tide_coverage || 0` turned a figure the payload did not carry
#     into a measured zero, in the four cards above the grid.
#
#   * `t.coverage_pct || 0` did the same to TIDE coverage, where it matters
#     most: a system with no coverage figure reported and a system measured
#     at nought percent are the same number on screen and opposite findings.
#     Nought percent is also the one that should be read as urgent, and the
#     colour band made it red either way, so the urgency was asserted for a
#     system nobody had measured.
#
#   * `data.systems || []` rendered "No systems found. Connect Elasticsearch
#     to see system data." So a payload that carried no system list at all,
#     which is what a refusal looks like, advised the reader to connect
#     Elasticsearch.
#
#   * The sparkline drew only when `tl.length > 1`, so a system with one
#     bucket of history and a system with none drew the same nothing. And
#     `Math.max(1, ...)` meant an all-zero timeline drew a flat line along
#     the bottom rather than saying no alerts landed in the window.

#: The TIDE coverage bands buildAdSysCard used, with their CSS variables.
TIDE_GOOD, TIDE_FAIR = 70, 40

#: The systems tab's default window. The route's Query default and the
#: view model's default are the same number, named once.
SYSTEMS_DEFAULT_HOURS = 168

#: The sparkline's box, from the page.
SYS_SPARK_W, SYS_SPARK_H = 320, 32

#: The severity pills, in the order the page emitted them.
SYS_SEV_PILLS = (("critical", "crit", "crit"), ("high", "high", "high"),
                 ("medium", "med", "med"), ("low", "low", "low"))


def tide_band(pct: Optional[float]) -> Optional[str]:
    """Which band a coverage figure falls in, or None when there is no
    figure. The page banded a missing figure as nought and painted it the
    danger colour, which asserts a finding about a system nobody measured.

    "good", "fair" and "poor" rather than the CSS variable each one used to
    return. The variable name was this stylesheet's answer to the question,
    and it travelled into the view model, which is the contract the
    fragment and anything else reading this route are built on. A reading
    of 81% is good whatever paints it; `var(--success)` is a fact about
    ION's current theme, and putting it here made every future renderer
    inherit the theme's vocabulary.
    """
    if pct is None:
        return None
    if pct >= TIDE_GOOD:
        return "good"
    if pct >= TIDE_FAIR:
        return "fair"
    return "poor"


def sys_spark(timeline: Any) -> Optional[dict]:
    """The sparkline polyline for one system's timeline, or None when there
    is no timeline to draw.

    Three outcomes, where the page had one. A timeline of one bucket is
    drawn as a single point rather than skipped, because a system with one
    hour of history is not a system with none. A timeline whose every bucket
    is zero reports itself as empty rather than drawing a flat line along
    the bottom, which `Math.max(1, ...)` produced and which reads as a real
    series that happens to be low.
    """
    if not isinstance(timeline, list) or not timeline:
        return None
    counts = []
    for t in timeline:
        value = _count(t.get("count")) if isinstance(t, dict) else None
        counts.append(value if value is not None else 0)
    peak = max(counts)
    if peak == 0:
        return {"points": None, "flat": True, "w": SYS_SPARK_W, "h": SYS_SPARK_H}
    step = SYS_SPARK_W / (len(counts) - 1) if len(counts) > 1 else 0
    points = " ".join(
        f"{i * step:.1f},{SYS_SPARK_H - c / peak * (SYS_SPARK_H - 4) - 2:.1f}"
        for i, c in enumerate(counts)
    )
    if len(counts) == 1:
        # One bucket is a point, not a line. A polyline of one pair draws
        # nothing, so it is given a second identical pair.
        points = f"{points} {SYS_SPARK_W:.1f},{points.split(',')[1]}"
    return {"points": points, "flat": False, "w": SYS_SPARK_W, "h": SYS_SPARK_H}


def sys_card(row: Any) -> Optional["SystemCard"]:
    """One system card's figures, or None for a row that is not a mapping."""
    if not isinstance(row, dict):
        return None
    name = str(row.get("system") or "unknown")
    severity = row.get("severity") if isinstance(row.get("severity"), dict) else {}
    pills = []
    for key, label, cls in SYS_SEV_PILLS:
        count = _count(severity.get(key))
        # Truthiness on the count, as the page had it: a severity measured at
        # zero is not a pill saying "0 crit".
        if count:
            pills.append({"count": count, "label": label, "cls": cls})
    tide = row.get("tide") if isinstance(row.get("tide"), dict) else None
    coverage = _number(tide.get("coverage_pct")) if tide else None
    return {
        "name": name,
        "initials": name[:2].upper(),
        "mapped": row.get("mapped") is True,
        "alert_count": _count(row.get("alert_count")),
        "pills": pills,
        "spark": sys_spark(row.get("timeline")),
        "tide": {
            "coverage_pct": coverage,
            "band": tide_band(coverage),
            "applied_rules": _count(tide.get("applied_rules")),
            "total_rules": _count(tide.get("total_rules")),
            "enabled_rules": _count(tide.get("enabled_rules")),
            "disabled_rules": _count(tide.get("disabled_rules")),
        } if tide else None,
    }


class TideView(TypedDict):
    """One system's TIDE coverage, as the panel states it."""
    coverage_pct: Optional[float]
    band: Optional[str]  # "good" | "fair" | "poor", or None when unmeasured
    applied_rules: Optional[int]
    total_rules: Optional[int]
    enabled_rules: Optional[int]
    disabled_rules: Optional[int]


class SparkView(TypedDict):
    """A sparkline, or the fact that every bucket was zero."""
    points: Optional[str]
    flat: bool
    w: int
    h: int


class SevPill(TypedDict):
    count: int
    label: str
    cls: str


class SystemCard(TypedDict):
    name: str
    initials: str
    mapped: bool
    alert_count: Optional[int]
    pills: list[SevPill]
    spark: Optional[SparkView]
    tide: Optional[TideView]


class SystemsView(TypedDict):
    """Everything the systems tab renders, named.

    This is the whole template context, not part of it, which is what lets
    the route hand it to render_view and answer either markup or JSON from
    one object. `hours` is in here rather than merged in by the route for
    the same reason: a model the caller has to complete is not a contract.

    Every figure is Optional because every one of them has a third outcome.
    None is "not reported by this read", which the fragment draws as an
    ellipsis, and it is not nought.
    """
    failed: bool
    degraded: bool
    reason: Optional[str]
    hours: int
    rows: Optional[list[SystemCard]]
    total_alerts: Optional[int]
    total_systems: Optional[int]
    mapped_systems: Optional[int]
    avg_coverage: Optional[float]


def sys_failed(reason: Optional[str] = None,
               hours: int = SYSTEMS_DEFAULT_HOURS) -> SystemsView:
    """The view for a read that did not happen, with its reason when the
    payload gave one."""
    return {"failed": True, "degraded": False, "reason": reason, "hours": hours,
            "rows": None, "total_alerts": None, "total_systems": None,
            "mapped_systems": None, "avg_coverage": None}


def sys_overview(payload: Any,
                 hours: int = SYSTEMS_DEFAULT_HOURS) -> SystemsView:
    """The systems tab's view, as failed or as the four figures plus the
    cards.

    `rows` is None when the payload carried no system list, so the grid can
    say the read did not answer rather than advising the reader to connect
    Elasticsearch, which is what "No systems found" did for a refusal.

    `es_failed` is the other half of that. get_system_overview merges the
    Elasticsearch systems with the CyAB namespace mappings out of ION's own
    database, so when Elasticsearch cannot be read there are two different
    answers depending on what is left:

      nothing          no ES and no mapping, so which systems exist is not
                       known. That is a failed read, and it names the reason
                       rather than telling the reader to connect the thing
                       whose absence is the reason.

      the mappings     ION knows these systems exist. The list is real and
                       the alert figures are not, so the cards render and
                       every count goes in as None. Zero would say the
                       estate was quiet when the truth is nobody counted.

    A payload that does not carry `es_failed` is not read as a failure.
    get_system_overview always sets it, so its absence is an unexpected
    shape rather than a signal, and treating it as one would turn every
    healthy render into a warning.
    """
    if not isinstance(payload, dict):
        return sys_failed(hours=hours)
    rows = _rows(payload, "systems")
    cards = [c for c in (sys_card(r) for r in rows) if c] if rows is not None else None

    es_failed = payload.get("es_failed") is True
    reason = payload.get("error") or None
    if es_failed and not cards:
        return sys_failed(reason, hours)

    if cards is not None and es_failed:
        # Every card is a CyAB mapping in this case, and the API gives those
        # an alert_count of 0 because it has nothing to put there.
        for card in cards:
            card["alert_count"] = None

    if cards is not None:
        # Mapped first, then by alert count, as the page sorted them. A card
        # with no count sorts last rather than as a zero.
        cards.sort(key=lambda c: (not c["mapped"],
                                  -(c["alert_count"] if c["alert_count"] is not None else -1)))
    return {
        "failed": False,
        "degraded": es_failed,
        "reason": reason,
        "hours": hours,
        "rows": cards,
        "total_alerts": None if es_failed else _count(payload.get("total_alerts")),
        "total_systems": _count(payload.get("total_systems")),
        "mapped_systems": _count(payload.get("mapped_systems")),
        "avg_coverage": _number(payload.get("avg_tide_coverage")),
    }


@router.get(
    "/alerts/systems",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(QUEUE_PERMISSION))],
)
async def alerts_systems_fragment(
    request: Request,
    hours: int = Query(SYSTEMS_DEFAULT_HOURS),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> Response:
    """The systems tab's grid, with the four figures above it out of band.

    Calls get_system_overview, the handler GET /api/analytics/system-overview
    runs, with explicit arguments. No Authorization header is constructed:
    the fragment is already authenticated as the viewer, which is the whole
    reason the page's hand-built one never mattered.

    The context is one SystemsView and nothing else, so render_view can
    answer this route's markup or the model itself to a caller that asks
    for JSON. Everything that decides what the reader sees is in that
    object, which is what makes it a contract rather than a detail of this
    template.
    """
    from ion.web.analytics_api import get_system_overview

    try:
        payload = await get_system_overview(
            hours=hours, current_user=current_user, session=session)
        view = sys_overview(payload, hours)
    except Exception:
        logger.exception("Alert systems fragment could not read the overview")
        view = sys_failed(hours=hours)
    return render_view(request, SYSTEMS_FRAGMENT, view)
