"""The GitLab issue browser, as server-rendered fragments.

gitlab.html built the connection banner, the issue cards, the label /
assignee / milestone selects, the issue detail and the comment thread with
`innerHTML`. Jinja renders those now. What stays in the page is the write
path the fragment must not grow a second copy of: creating an issue,
adding a comment, and closing or reopening one still POST to
`/api/gitlab/*`, then ask htmx to re-request the fragment.

Permission is ``template:read``, the gate on every GET this page's
JavaScript called (`/api/gitlab/config`, `/test`, `/issues`,
`/issues/{iid}`, `/issues/{iid}/comments`, `/labels`, `/members`,
`/milestones`). `tools/fragment_plan.py gitlab` reads that off the live
routes. The page itself is `require_page_auth`, which is softer; the
fragment matches the read API, not the page, or it would be a softer way
in than the endpoint it mirrors.

``require_de_module`` is intentionally absent. `gitlab_router` is mounted
at `/api` with no licence dependency (`server.py`), and a module not named
`de_*` is not in the fragment registry's gated prefixes. GitLab is not the
detection-engineering module. Putting that gate first would answer 404 on
a deployment that has GitLab and is not licensed for detection
engineering, while the JSON routes this fragment calls would still be
there. The 404 would be a lie.

The reads are the endpoint functions in `ion.web.gitlab_api`, not a second
copy of them. `list_gitlab_issues` is the one that merges "assigned to me"
with "authored by me" when `my_issues` is set; the page's scope select
says `my` / `all`, which is that flag, not GitLab's own `scope`
(`created_by_me` / `assigned_to_me`). Passing `my` through as `scope`
would ask GitLab for a scope it does not have.

Each of those functions closes the process-wide GitLab client in a
`finally`. Calling two of them at once can close the client under the
other, so the calls here are sequential on purpose.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from ion.auth.dependencies import require_permission
from ion.models.user import User
from ion.web import gitlab_api
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)

router = APIRouter()

#: The permission every GitLab GET names. One spelling, so the five
#: fragments and the endpoints they mirror cannot drift apart one at a time.
PERMISSION = "template:read"

FRAGMENT = "_fragments/gitlab.html"

#: What the JavaScript asked for. The JSON endpoint's own default is 20,
#: and the page overrode it; a fragment that forgot the override would
#: silently show a shorter list than the page it replaced.
_ISSUES_PER_PAGE = 50

_HEX_COLOR = re.compile(r"^#[0-9A-Fa-f]{3,8}$")
_FALLBACK_COLOR = "#6c757d"

_PHASE_EVENT = {
    "connected": "gitlab-ready",
    "unconfigured": "gitlab-unconfigured",
    "refused": "gitlab-unconfigured",
}


def flags_phase(enabled: object, has_token: object) -> str:
    """Whether the stored flags say we may call the connection test.

    Three answers, and a non-boolean is the third. ``0`` and ``"no"`` are
    not ``False``: folding them into "not configured" sends the operator to
    reconfigure a connection we never actually judged.
    """
    if enabled is False or has_token is False:
        return "unconfigured"
    if enabled is True and has_token is True:
        return "ready"
    return "unknown"


def result_phase(connected: object) -> str:
    """What a connection test answered, once we actually ran one.

    ``connected is False`` is a refusal. ``"no"`` and ``0`` are not: one is
    truthy and the JavaScript's ``if (testResult.connected)`` would have
    called it connected, the other is falsy and ``if (!connected)`` would
    have called it refused. Neither is a boolean, so the state is unknown.
    """
    if connected is True:
        return "connected"
    if connected is False:
        return "refused"
    return "unknown"


def _blank_to_none(value: Optional[str]) -> Optional[str]:
    """``""`` means the control is unset. ``"0"`` is a real search.

    ``int(value) or None`` is the bug this exists to avoid: a search for
    the issue whose title is ``0`` becomes "no search", and the list that
    comes back is every issue.
    """
    if value is None or value == "":
        return None
    return value


def _safe_color(raw: object) -> str:
    """A GitLab label colour, or the neutral fallback.

    The value is emitted as ``data-ion-style="background: <color>"`` and
    applied with ``setProperty``. Anything that is not a bare hex colour
    is not a colour: ``#fff; background: url(...)`` would otherwise ride
    along as a second declaration.
    """
    if isinstance(raw, str) and _HEX_COLOR.fullmatch(raw.strip()):
        return raw.strip()
    return _FALLBACK_COLOR


def _as_text(value: object) -> Optional[str]:
    """A string field, or None when the payload did not send one.

    An integer is not a project path and not an error message. Printing it
    would turn "the key was the wrong type" into a value the analyst reads
    as data. Empty string is the same as absent.
    """
    if isinstance(value, str) and value != "":
        return value
    return None


def _payload_list(payload: object, key: str) -> Optional[list]:
    """The list under ``key``, or None if the payload did not carry one.

    ``None`` and ``[]`` are different claims. A missing key, a non-dict
    body, or a key whose value is not a list means we did not get a list,
    which is not the same sentence as "GitLab has none".
    """
    if not isinstance(payload, dict) or key not in payload:
        return None
    value = payload[key]
    if not isinstance(value, list):
        return None
    return value


def _color_map(labels: object) -> dict[str, str]:
    colors: dict[str, str] = {}
    if not isinstance(labels, list):
        return colors
    for label in labels:
        if not isinstance(label, dict):
            continue
        name = label.get("name")
        if name is None:
            continue
        colors[str(name)] = _safe_color(label.get("color"))
    return colors


def _issue_view(issue: object, colors: dict[str, str]) -> Optional[dict[str, Any]]:
    """One issue shaped for the template, or None if it is not an object.

    A non-dict row is skipped rather than rendered as the word None. Numbers
    stay numbers: ``iid`` 0 and a title of 0 are measurements, and the
    template decides with ``is not none`` what to do with them. ``state``
    goes through ``plain`` because a SQLEnum member renders as
    ``Enum.MEMBER`` under ``str()`` on 3.12, and the pill would say that
    instead of ``opened``.
    """
    if not isinstance(issue, dict):
        return None
    state = plain(issue.get("state"))
    state = None if state is None else str(state)
    labels = []
    for label in issue.get("labels") or []:
        if label is None:
            continue
        name = label if isinstance(label, str) else plain(label)
        if name is None:
            continue
        text = str(name)
        labels.append({"name": name, "color": colors.get(text, _FALLBACK_COLOR)})
    assignees = []
    for assignee in issue.get("assignees") or []:
        if assignee is None:
            continue
        shown = assignee if isinstance(assignee, str) else plain(assignee)
        if shown is None:
            continue
        assignees.append(shown)
    return {
        "iid": issue.get("iid"),
        "title": issue.get("title"),
        "state": state,
        "labels": labels,
        "assignees": assignees,
        "author": issue.get("author"),
        "created_at": issue.get("created_at"),
        "updated_at": issue.get("updated_at"),
        "due_date": issue.get("due_date"),
        "description": issue.get("description"),
        "milestone": issue.get("milestone"),
        "web_url": issue.get("web_url") if isinstance(issue.get("web_url"), str) else None,
    }


def _comment_view(comment: object) -> Optional[dict[str, Any]]:
    if not isinstance(comment, dict):
        return None
    # `list_issue_comments` already drops system notes. A note that still
    # says it is one is not a person's comment, and showing it as one would
    # disagree with the endpoint this route calls.
    if comment.get("system") is True:
        return None
    return {
        "author": comment.get("author"),
        "created_at": comment.get("created_at"),
        "body": comment.get("body"),
    }


def _label_rows(
    labels: Optional[list], selected_filter: Optional[str], selected_multi: set[str]
) -> Optional[list[dict[str, Any]]]:
    if labels is None:
        return None
    rows = []
    for label in labels:
        if not isinstance(label, dict):
            continue
        name = label.get("name")
        if name is None:
            continue
        rows.append({
            "name": name,
            "filter_selected": (
                selected_filter is not None and str(name) == selected_filter
            ),
            "multi_selected": str(name) in selected_multi,
        })
    return rows


def _member_rows(
    members: Optional[list], selected: Optional[str]
) -> Optional[list[dict[str, Any]]]:
    if members is None:
        return None
    rows = []
    for member in members:
        if not isinstance(member, dict):
            continue
        mid = member.get("id")
        # ``is None``, not truthiness. A member id of 0 is a real id.
        if mid is None:
            continue
        rows.append({
            "id": mid,
            "name": member.get("name"),
            "username": member.get("username"),
            "selected": selected is not None and str(mid) == selected,
        })
    return rows


def _milestone_rows(
    milestones: Optional[list], selected: Optional[str]
) -> Optional[list[dict[str, Any]]]:
    if milestones is None:
        return None
    rows = []
    for milestone in milestones:
        if not isinstance(milestone, dict):
            continue
        mid = milestone.get("id")
        if mid is None:
            continue
        rows.append({
            "id": mid,
            "title": milestone.get("title"),
            "selected": selected is not None and str(mid) == selected,
        })
    return rows


def _fragment(
    request: Request, context: dict[str, Any], event: Optional[str] = None
) -> HTMLResponse:
    headers = {"HX-Trigger": event} if event else None
    return templates.TemplateResponse(
        request=request, name=FRAGMENT, context=context, headers=headers
    )


def _status(request: Request, phase: str, **extra: Any) -> HTMLResponse:
    context: dict[str, Any] = {"view": "status", "phase": phase, "error": None}
    context.update(extra)
    return _fragment(request, context, _PHASE_EVENT.get(phase))


async def _read_list(key: str, start: Any) -> Optional[list]:
    """One catalogue read. None means it failed; [] means GitLab has none.

    ``start`` is called inside the try, so a stub that raises while building
    the coroutine is still a failed catalogue read and not a 500.
    """
    try:
        payload = await start()
    except Exception:
        logger.exception("GitLab %s could not be read", key)
        return None
    return _payload_list(payload, key)


@router.get("/gitlab/status", response_class=HTMLResponse)
async def gitlab_status(
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION)),
) -> HTMLResponse:
    """The connection banner.

    Config first, and the test only when both flags are the boolean True.
    A thrown read is its own phase: it is not "connection failed" (GitLab
    answered no) and not "not configured" (the flags said so).
    """
    try:
        config = await gitlab_api.get_gitlab_config_endpoint(current_user)
    except Exception:
        logger.exception("GitLab configuration could not be read")
        return _status(request, "failed")
    if not isinstance(config, dict):
        return _status(request, "unknown")

    phase = flags_phase(config.get("enabled"), config.get("has_token"))
    if phase == "unconfigured":
        return _status(request, "unconfigured")
    if phase == "unknown":
        return _status(request, "unknown")

    try:
        result = await gitlab_api.test_gitlab_connection(current_user)
    except Exception:
        logger.exception("GitLab connection test could not be read")
        return _status(request, "failed")

    connected = result.get("connected") if isinstance(result, dict) else None
    phase = result_phase(connected)
    project_path = _as_text(result.get("project_path")) if isinstance(result, dict) else None
    web_url = _as_text(result.get("web_url")) if isinstance(result, dict) else None
    error = None
    if phase == "refused" and isinstance(result, dict):
        error = _as_text(result.get("error"))
    # The token and the instance URL are not passed through. The config
    # endpoint already withholds the token; dropping every other key here
    # means a future field on that dict cannot land in the banner by accident.
    return _status(
        request, phase, project_path=project_path, web_url=web_url, error=error
    )


@router.get("/gitlab/issues", response_class=HTMLResponse)
async def gitlab_issues(
    request: Request,
    state: Literal["all", "opened", "closed"] = Query("all"),
    scope: Literal["my", "all"] = Query("my"),
    labels: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(require_permission(PERMISSION)),
) -> HTMLResponse:
    """The issue cards.

    ``scope`` is the page's select (``my`` / ``all``), mapped to
    ``my_issues``. GitLab's ``scope`` argument is passed ``None`` so the
    page word "my" is not forwarded as a scope GitLab does not define.
    ``state`` and ``scope`` are constrained: a value the endpoint cannot
    use is a 422, not a fragment that says the read failed.
    """
    # Colours first, then the list. Sequential because each endpoint closes
    # the shared client. A failed colour read is not a failed issue read:
    # the chips fall back to the neutral colour, and the cards still say
    # what GitLab returned.
    try:
        label_payload = await gitlab_api.list_gitlab_labels(current_user=current_user)
        colors = _color_map(_payload_list(label_payload, "labels") or [])
    except Exception:
        logger.exception("GitLab label colours could not be read")
        colors = {}

    try:
        payload = await gitlab_api.list_gitlab_issues(
            state=state,
            labels=_blank_to_none(labels),
            search=_blank_to_none(search),
            per_page=_ISSUES_PER_PAGE,
            page=1,
            scope=None,
            my_issues=(scope == "my"),
            current_user=current_user,
        )
    except Exception:
        logger.exception("GitLab issues could not be read")
        return _fragment(request, {"view": "issues", "failed": True, "issues": None})

    issues = _payload_list(payload, "issues")
    if issues is None:
        return _fragment(request, {"view": "issues", "failed": True, "issues": None})
    views = [view for raw in issues if (view := _issue_view(raw, colors)) is not None]
    return _fragment(
        request, {"view": "issues", "failed": False, "issues": views}
    )


@router.get("/gitlab/issues/{issue_iid}", response_class=HTMLResponse)
async def gitlab_issue_detail(
    issue_iid: int,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION)),
) -> HTMLResponse:
    """One issue.

    This route declares none of the list filters. Issue cards are rendered
    inside ``#issues-list``, which sends those filters with ``hx-include``,
    and htmx inherits that onto the card's own request. Declaring them here
    would 422 on an empty ``state`` the moment a card was clicked. They are
    ignored, which is what "the card shows this issue" means.

    404 is not a failed read: GitLab answered, and it has no such issue.
    Any other error is a failed read, and neither one is rendered as an
    empty issue.
    """
    not_found = False
    try:
        payload = await gitlab_api.get_gitlab_issue(issue_iid, current_user=current_user)
    except HTTPException as exc:
        if exc.status_code == 404:
            not_found = True
            payload = None
        else:
            logger.exception("GitLab issue %s could not be read", issue_iid)
            payload = None
    except Exception:
        logger.exception("GitLab issue %s could not be read", issue_iid)
        payload = None

    if not_found:
        return _fragment(request, {
            "view": "detail", "failed": False, "not_found": True,
            "iid": issue_iid, "issue": None,
        })
    if not isinstance(payload, dict):
        return _fragment(request, {
            "view": "detail", "failed": True, "not_found": False,
            "iid": issue_iid, "issue": None,
        })

    try:
        label_payload = await gitlab_api.list_gitlab_labels(current_user=current_user)
        colors = _color_map(_payload_list(label_payload, "labels") or [])
    except Exception:
        logger.exception("GitLab label colours could not be read")
        colors = {}

    view = _issue_view(payload, colors)
    if view is None:
        return _fragment(request, {
            "view": "detail", "failed": True, "not_found": False,
            "iid": issue_iid, "issue": None,
        })
    # The path iid is the issue the analyst asked for. A payload that omits
    # it must not be rendered as a blank number, and 0 must not be replaced
    # with "nothing" by a truthiness check.
    if view.get("iid") is None:
        view["iid"] = issue_iid
    return _fragment(request, {
        "view": "detail", "failed": False, "not_found": False,
        "iid": issue_iid, "issue": view,
    })


@router.get("/gitlab/issues/{issue_iid}/comments", response_class=HTMLResponse)
async def gitlab_issue_comments(
    issue_iid: int,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION)),
) -> HTMLResponse:
    """The comment thread. Same inherited-filter reason as the detail route.

    ``per_page`` is left at the endpoint's default (20). The issues list
    overrides to 50 because the page did; comments did not, and a second
    copy of that override would disagree with the JSON the page used to call.
    """
    try:
        payload = await gitlab_api.list_gitlab_issue_comments(
            issue_iid, current_user=current_user
        )
    except HTTPException as exc:
        not_found = exc.status_code == 404
        if not not_found:
            logger.exception("GitLab comments on issue %s could not be read", issue_iid)
        return _fragment(request, {
            "view": "comments", "failed": not not_found, "not_found": not_found,
            "iid": issue_iid, "comments": None,
        })
    except Exception:
        logger.exception("GitLab comments on issue %s could not be read", issue_iid)
        return _fragment(request, {
            "view": "comments", "failed": True, "not_found": False,
            "iid": issue_iid, "comments": None,
        })

    comments = _payload_list(payload, "comments")
    if comments is None:
        return _fragment(request, {
            "view": "comments", "failed": True, "not_found": False,
            "iid": issue_iid, "comments": None,
        })
    views = [view for raw in comments if (view := _comment_view(raw)) is not None]
    return _fragment(request, {
        "view": "comments", "failed": False, "not_found": False,
        "iid": issue_iid, "comments": views,
    })


@router.get("/gitlab/catalog", response_class=HTMLResponse)
async def gitlab_catalog(
    request: Request,
    labels: Optional[str] = None,
    assignee_id: Optional[str] = None,
    milestone_id: Optional[str] = None,
    issue_labels: Optional[list[str]] = Query(None),
    current_user: User = Depends(require_permission(PERMISSION)),
) -> HTMLResponse:
    """The three selects, out of band, plus a note about any read that failed.

    The selects cannot live only in the page: only this response knows the
    options. They are re-rendered on failure as well, including the value
    the page currently holds, so a failed refresh does not delete the
    control or forget a selection of ``"0"``. The note in the swap target
    is what says the empty-looking select is a failed read rather than a
    project with no labels.

    ``state`` and ``scope`` are not declared. The reload button includes the
    filter selects, and those names belong to the issue list.
    """
    selected_filter = _blank_to_none(labels)
    selected_assignee = _blank_to_none(assignee_id)
    selected_milestone = _blank_to_none(milestone_id)
    # None is "the control sent nothing". [] would mean the same here, and
    # a name of "0" is a selection, so this does not use truthiness on the
    # names themselves.
    chosen = [] if issue_labels is None else issue_labels
    selected_multi = {item for item in chosen if item != ""}

    label_rows = _label_rows(
        await _read_list(
            "labels", lambda: gitlab_api.list_gitlab_labels(current_user=current_user)
        ),
        selected_filter,
        selected_multi,
    )
    member_rows = _member_rows(
        await _read_list(
            "members", lambda: gitlab_api.list_gitlab_members(current_user=current_user)
        ),
        selected_assignee,
    )
    milestone_rows = _milestone_rows(
        await _read_list(
            "milestones",
            lambda: gitlab_api.list_gitlab_milestones(current_user=current_user),
        ),
        selected_milestone,
    )
    return _fragment(request, {
        "view": "catalog",
        "labels": label_rows,
        "members": member_rows,
        "milestones": milestone_rows,
        "selected_label": selected_filter,
        "selected_assignee": selected_assignee,
        "selected_milestone": selected_milestone,
        "selected_issue_labels": sorted(selected_multi),
    })
