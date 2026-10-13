"""Alerts: the case side and the playbook region, as server-rendered fragments.

alerts.html is converted a region at a time, in the order scratchpad
alerts_plan.md sets out, and this module grows a route per region. Stage 2
is the case side: the Cases card in the side panel, the slide-out case
panel, the Add-to-Case picker, the case management modal and the AI case
summary. Stage 3 is the playbook region: the executions list in the case
management modal, the Start Playbook picker, the Investigation Playbooks
section of the alert detail modal and its Browse Playbook Library panel.
The alert queue, the analytics panels and the rest of the alert detail
modal are later stages and are not in here.

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
import re
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from markupsafe import Markup, escape
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, templates

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
) -> HTMLResponse:
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

    return templates.TemplateResponse(
        request=request,
        name=SUMMARY_FRAGMENT,
        context={
            "failed": failed,
            "cases": rows,
            "active_total": total,
            "facets_failed": facets_failed,
            "limit": SUMMARY_LIMIT,
        },
        status_code=200,
    )


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
) -> HTMLResponse:
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

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=PANEL_FRAGMENT,
            context={"case_id": case_id, "can_update": can_update,
                     "status_options": STATUS_OPTIONS,
                     "severity_options": SEVERITY_OPTIONS, **ctx},
            status_code=200,
        )

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
) -> HTMLResponse:
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
        return templates.TemplateResponse(
            request=request, name=PICKER_FRAGMENT,
            context={"failed": True, "cases": None, "total": None,
                     "truncated": False, "selected": selected,
                     "can_add": can_add},
            status_code=200,
        )
    return templates.TemplateResponse(
        request=request, name=PICKER_FRAGMENT,
        context={"failed": False, "selected": selected, "can_add": can_add,
                 **listing},
        status_code=200,
    )


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
) -> HTMLResponse:
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

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=MANAGE_FRAGMENT,
            context={"case_id": case_id, "status_options": STATUS_OPTIONS,
                     "severity_options": SEVERITY_OPTIONS, **flags, **ctx},
            status_code=200,
        )

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
) -> HTMLResponse:
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

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=AI_SUMMARY_FRAGMENT,
            context={"case_id": case_id, **ctx}, status_code=200,
        )

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
) -> HTMLResponse:
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

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=CASE_EXECUTIONS_FRAGMENT,
            context={"case_id": case_id, **ctx}, status_code=200,
        )

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
) -> HTMLResponse:
    """The Start Playbook picker for a case, the overlay included.

    Lists through the handler GET /api/playbooks?active_only=true runs.
    Start is offered only with playbook:execute, which POST
    /api/cases/{id}/playbook/{pid}/start carries; the page offered it to
    every reader. An empty list is a dialog that says so, where the page
    showed a toast and no dialog.
    """
    from ion.web.api import list_playbooks

    can_start = _can(current_user, PLAYBOOK_EXECUTE_PERMISSION)

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=CASE_PLAYBOOK_PICKER_FRAGMENT,
            context={"case_id": case_id, "can_start": can_start, **ctx},
            status_code=200,
        )

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
) -> HTMLResponse:
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

    return templates.TemplateResponse(
        request=request, name=ALERT_PLAYBOOKS_FRAGMENT,
        context={
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
        },
        status_code=200,
    )


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
) -> HTMLResponse:
    """The Browse Playbook Library panel under the alert's section.

    Lists through the handler GET .../suggested-playbooks runs. Same four
    outcomes as the recommendations: missing alert, failed read with the
    reason, nothing in the library that matches, or the two groups.
    `togglePlaybookLibrary` had a failure string and `data.playbooks || []`.
    """
    from ion.web.api import get_suggested_playbooks

    can_start = _can(current_user, PLAYBOOK_EXECUTE_PERMISSION)

    def answer(ctx: dict) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request, name=PLAYBOOK_LIBRARY_FRAGMENT,
            context={"alert_id": alert_id, "can_start": can_start, **ctx},
            status_code=200,
        )

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
