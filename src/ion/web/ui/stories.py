"""The Stories page, as four server-rendered fragments.

stories.html fetched five URLs and built its whole body with `innerHTML`:
nine write sites and 297 lines of inline JavaScript with a hand-rolled
`esc()`. The nine sites are five separate things, and they are five because
each is re-requested on its own:

  * the story rail (three sites: rows, "No stories yet", "Failed to load"),
  * the step-type catalogue (one site),
  * the detail editor (two sites: the form, and the post-delete notice),
  * a story's run history (two sites: the table and "No runs yet."),
  * the validation-error block (one site).

Four of those are fragments here. The validation block is not: it renders a
response the browser already holds, from the POST or PUT it just made, so
it has nowhere to be requested from. Its chrome is static markup in the
editor fragment and the page sets `textContent` on it, which builds no
markup and so still passes the redesign's `server` column.

Why four routes rather than one. The rail and the pane are re-requested
independently: opening a story replaces the pane and re-renders the rail to
move the highlight, and a save replaces both. The run table is re-requested
on its own after a run, without re-rendering the editor, because
re-rendering the editor would overwrite a DAG the analyst has edited and
not saved. Folding runs into the editor would make "show the new run" cost
the user their unsaved work. The catalogue is the fourth because it is a
region with its own failure: the JavaScript's `catch (e) { }` meant a failed
catalogue read showed an empty space where the step types should be, and a
reader cannot tell that from a build with no step types.

The page route `/stories` is gated on `require_page_auth`, meaning any
logged-in user, while every API it reads is gated on `playbook:read`. So
the page is softer than its own data, and an account without the permission
could open it and watch every fetch 403 into "Failed to load", which was
not true: nothing had failed, and nothing was missing. These fragments
carry `playbook:read`, matching the endpoints they mirror, and
static/js/htmx-errors.js renders a 403 as "You do not have permission to
view this. Nothing is missing from the system: this account cannot read
it." The page gate itself is not changed here; it lives in story_api.py and
widening or narrowing a page gate is its owner's call.

Two of the conversion rules have no site on this page, which is worth
stating rather than leaving as an omission. `ui._shared.plain` is for
SQLEnum columns: `StoryRun.status` is a plain `String(32)` and
`Story.enabled` is a `Boolean`, so no column here carries an enum member.
`safe_url` is for a stored URL rendered as a link: the only URL this page
can show is the `url` key inside an `http_request` step's config, and that
is rendered as JSON text inside a textarea and a `<pre>`, never as an href.
"""
from __future__ import annotations

import json
import logging
from enum import Enum
from typing import Any, NamedTuple

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import templates

logger = logging.getLogger(__name__)

router = APIRouter()

LIST_FRAGMENT = "_fragments/stories_list.html"
STEP_TYPES_FRAGMENT = "_fragments/stories_step_types.html"
EDITOR_FRAGMENT = "_fragments/stories_editor.html"
RUNS_FRAGMENT = "_fragments/stories_runs.html"

#: The permission all four reads carry, matching GET /api/stories,
#: GET /api/stories/{id}, GET /api/stories/{id}/runs and
#: GET /api/stories/step-types. One name, so the four fragments and the four
#: endpoints they mirror cannot drift apart one at a time.
READ_PERMISSION = "playbook:read"

#: What each button in the editor costs, read off the endpoint it posts to.
#: The editor offers a button only when the account holds its permission.
#: This page is reachable by any logged-in user, so an account with
#: `playbook:read` and nothing else is a real account, and showing it a
#: Delete button that can only answer 403 is a worse answer than no button.
#: detection_health.py gates its Propose control the same way.
ACTION_PERMISSIONS = {
    "create": "playbook:create",
    "update": "playbook:update",
    "execute": "playbook:execute",
    "delete": "playbook:delete",
}

#: How many runs the rail's run table shows. `?limit=10` was in the
#: JavaScript, and the heading says how many are shown, so the two have to
#: agree.
RUNS_LIMIT = 10

#: Run status to the badge that paints it. A table rather than a chain of
#: ternaries, and `.get` with a default, because `StoryRun.status` is a
#: plain String column: "cancelled" and "pending" are both legal values the
#: JavaScript's two-way ternary already dropped into the neutral badge.
RUN_STATUS_BADGES = {
    "completed": "badge-success",
    "failed": "badge-error",
}
NEUTRAL_RUN_BADGE = "badge-ghost"

#: How much of an alert id the run table shows. The JavaScript sliced to 24
#: and said nothing, so two alerts sharing a 24-character prefix rendered
#: identically. The slice stays, and the template puts the whole value in a
#: title, because an id a reader has to copy is worse truncated silently.
ALERT_ID_CHARS = 24

#: The blank story "+ New story" starts from. It was a JavaScript literal
#: wrapped in `{% raw %}` so Jinja would not read its `{{ trigger.case_id }}`
#: as template syntax. As a Python value it needs no escaping trick, and
#: there is now one definition of what a new story looks like.
BLANK_DAG: dict[str, Any] = {
    "name": "New story",
    "schema_version": 1,
    "start": "note",
    "nodes": [
        {
            "id": "note",
            "type": "case_note",
            "config": {
                "case_id": "{{ trigger.case_id }}",
                "content": "Hello from a story.",
            },
            "next": None,
        }
    ],
}

BLANK_STORY: dict[str, Any] = {
    "id": None,
    "name": "New story",
    "description": "",
    "enabled": True,
    "dag": BLANK_DAG,
}


class DetailState(str, Enum):
    """What the detail pane is showing.

    Five states, named, because the pane had five and they were spread
    across two `innerHTML` writes and a `${s.id ? ... : ''}` ternary. An
    enum keeps "the read failed" and "the story is gone" distinct from each
    other and from "no story selected", which is the distinction the old
    page lost: a failed fetch called `showToast` and left whatever was in
    the pane before, so the screen kept showing a story that may not exist.
    """

    IDLE = "idle"
    NEW = "new"
    EDIT = "edit"
    MISSING = "missing"
    FAILED = "failed"


def detail_state(story_id: int | None, mode: str) -> DetailState:
    """Which pane state a request asks for.

    `story_id` wins over `mode`, so a request carrying both is an edit
    rather than ambiguous. Anything other than "new" in `mode` is idle: the
    parameter comes off a button in the page shell, and a value nobody
    recognises must not open a form that posts.
    """
    if story_id is not None:
        return DetailState.EDIT
    if mode == "new":
        return DetailState.NEW
    return DetailState.IDLE


def selected_id(raw: str) -> int | None:
    """The rail's highlighted story id, out of the page's hidden input.

    The input is empty whenever nothing is selected, and an empty string is
    not a story id, so this parses rather than letting FastAPI reject the
    request with a 422 that htmx would render as a server failure. A value
    that is not a number highlights nothing, which is the same outcome as
    an empty one and not worth failing the whole rail over.
    """
    text = (raw or "").strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def dag_text(dag: Any) -> str:
    """A story's DAG as the textarea's contents.

    `JSON.stringify(s.dag || {}, null, 2)` is what the JavaScript put there.
    Key order is preserved through json.loads and json.dumps, so the text a
    reader sees is the text that was stored.
    """
    try:
        return json.dumps(dag if dag is not None else {}, indent=2, default=str)
    except (TypeError, ValueError):
        # A DAG that will not serialise is still editable as an empty
        # object, which beats a 500 that takes the whole pane away.
        logger.exception("Story DAG could not be re-serialised for the editor")
        return "{}"


class Actions(NamedTuple):
    """Which editor buttons this account can actually use.

    A NamedTuple rather than a dict because Jinja resolves `can.update` as
    an attribute first, and a dict has an `update` *method*. That method is
    truthy, so `{% if can.update %}` was true for every account and the
    Save button rendered for a reader with no write permission at all. The
    field names here are real attributes, so the collision cannot recur.
    """

    create: bool
    update: bool
    execute: bool
    delete: bool

    @property
    def any_on_a_saved_story(self) -> bool:
        return self.update or self.execute or self.delete


def allowed_actions(user: User | None) -> Actions:
    """The four permissions this account holds, read one at a time.

    Keyed off ACTION_PERMISSIONS so the mapping from a button to the
    endpoint's permission has one definition, and the field names match its
    keys so adding a fifth action is one line in each.
    """
    return Actions(**{
        name: bool(user and user.has_permission(permission))
        for name, permission in ACTION_PERMISSIONS.items()
    })


def run_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """One view dict per run row, newest first as the query sorted them."""
    rows: list[dict[str, Any]] = []
    for run in payload.get("runs") or []:
        status = run.get("status")
        # An alert id of "" renders the same empty cell as no alert at all,
        # so it is treated as no alert rather than as an id the reader is
        # expected to copy.
        alert_id = run.get("alert_id")
        if isinstance(alert_id, str) and not alert_id.strip():
            alert_id = None
        rows.append({
            "id": run.get("id"),
            "status": status,
            "badge": RUN_STATUS_BADGES.get(status, NEUTRAL_RUN_BADGE),
            "started_at": run.get("started_at"),
            # Passed through as it is, including 0 and None, so the template
            # is the one place that decides what each means. The
            # JavaScript's `r.case_id ? r.case_id : ''` blanked case 0 here,
            # which reads as a run with no case bound at all.
            "case_id": run.get("case_id"),
            "alert_id": alert_id,
            "alert_id_short": (None if alert_id is None
                               else str(alert_id)[:ALERT_ID_CHARS]),
            "alert_id_clipped": (alert_id is not None
                                 and len(str(alert_id)) > ALERT_ID_CHARS),
            "step_outputs": _pretty(run.get("step_outputs")),
            "error": run.get("error"),
        })
    return rows


def _pretty(value: Any) -> str:
    """A step-output blob as the `<pre>` showed it.

    `JSON.stringify(r.step_outputs, null, 2)` on an absent value produced
    the string "undefined" in the old page. A run with no captured outputs
    gets an empty object here, which is what the row actually means: the run
    recorded nothing, rather than the field being a word.
    """
    try:
        return json.dumps(value if value is not None else {}, indent=2,
                          default=str)
    except (TypeError, ValueError):
        return "{}"


@router.get(
    "/stories/list",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(READ_PERMISSION))],
)
def stories_list_fragment(
    request: Request,
    story_id: str = Query("", description="The rail's highlighted story"),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The story rail.

    Calls story_api.list_payload, the function GET /api/stories calls, so
    the rail and the API cannot disagree about which stories exist or in
    what order. `playbook:read` matches that endpoint exactly.
    """
    from ion.web.story_api import list_payload

    try:
        payload = list_payload(session)
    except Exception:
        logger.exception("Stories rail could not be rendered")
        # Not an empty rail. "No stories yet" invites someone to create the
        # story they already have, and the old page's "Failed to load" said
        # a load had failed without saying that nothing about the estate is
        # known from it.
        return templates.TemplateResponse(
            request=request,
            name=LIST_FRAGMENT,
            context={"failed": True, "stories": [], "active_id": None},
        )

    return templates.TemplateResponse(
        request=request,
        name=LIST_FRAGMENT,
        context={
            "failed": False,
            "stories": payload.get("stories") or [],
            "active_id": selected_id(story_id),
        },
    )


@router.get(
    "/stories/step-types",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(READ_PERMISSION))],
)
def stories_step_types_fragment(request: Request) -> HTMLResponse:
    """The catalogue of step types the executor knows how to run.

    Calls story_executor.list_step_types, the function
    GET /api/stories/step-types calls. `playbook:read` matches it.
    """
    from ion.services import story_executor

    try:
        step_types = story_executor.list_step_types()
    except Exception:
        logger.exception("Step-type catalogue could not be rendered")
        # The JavaScript swallowed this failure entirely, so a broken
        # catalogue read left blank space where the step types belong and a
        # reader would conclude the executor supports none.
        return templates.TemplateResponse(
            request=request,
            name=STEP_TYPES_FRAGMENT,
            context={"failed": True, "step_types": []},
        )

    return templates.TemplateResponse(
        request=request,
        name=STEP_TYPES_FRAGMENT,
        context={"failed": False, "step_types": step_types or []},
    )


@router.get(
    "/stories/editor",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(READ_PERMISSION))],
)
def stories_editor_fragment(
    request: Request,
    story_id: str = Query("", description="The story to edit, or empty"),
    mode: str = Query("", description="'new' for a blank story"),
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """The detail pane: the idle prompt, a blank story, or one story's form.

    Calls story_api.story_payload, the function GET /api/stories/{id} calls,
    so the DAG in the textarea is the DAG the API would hand a script.
    `playbook:read` matches that endpoint.

    The pane's chrome wraps every state, including the two failure ones, so
    a story that has been deleted since the rail was rendered leaves a
    readable pane rather than a stranded one.

    `story_id` arrives as a string because the page sends it with
    `hx-include` from a hidden input that is empty whenever nothing is
    selected. Declared as `int | None` it would make an empty selection a
    422, which htmx renders as "the server failed to produce this" when
    nothing failed and nothing is selected. It is parsed here instead, at
    the boundary.
    """
    from ion.web.story_api import story_payload

    selected = selected_id(story_id)
    state = detail_state(selected, mode)
    context: dict[str, Any] = {
        "state": state.value,
        "story_id": selected,
        "story": None,
        "dag_text": "",
        "can": allowed_actions(current_user),
    }

    if state is DetailState.NEW:
        context["story"] = BLANK_STORY
        context["dag_text"] = dag_text(BLANK_DAG)
    elif state is DetailState.EDIT:
        try:
            story = story_payload(session, selected)
        except Exception:
            logger.exception("Story %r could not be read for the editor",
                             selected)
            # Distinct from MISSING on purpose. "This story was deleted" and
            # "we could not look it up" lead to opposite actions, and one of
            # them is to recreate a story that still exists.
            context["state"] = DetailState.FAILED.value
            return templates.TemplateResponse(
                request=request, name=EDITOR_FRAGMENT, context=context,
            )
        if story is None:
            context["state"] = DetailState.MISSING.value
        else:
            context["story"] = story
            context["dag_text"] = dag_text(story.get("dag"))

    return templates.TemplateResponse(
        request=request, name=EDITOR_FRAGMENT, context=context,
    )


@router.get(
    "/stories/runs",
    response_class=HTMLResponse,
    dependencies=[Depends(require_permission(READ_PERMISSION))],
)
def stories_runs_fragment(
    request: Request,
    story_id: int = Query(..., description="The story whose runs to show"),
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    """One story's recent runs.

    Calls story_api.runs_payload, the function GET /api/stories/{id}/runs
    calls, rather than repeating the ordering and the limit cap.
    `playbook:read` matches that endpoint.

    It is its own route, not part of the editor, so that re-requesting the
    run table after a run does not replace the DAG textarea and discard an
    edit the analyst has not saved.
    """
    from ion.web.story_api import runs_payload

    try:
        payload = runs_payload(session, story_id, limit=RUNS_LIMIT)
    except Exception:
        logger.exception("Run history for story %r could not be rendered",
                         story_id)
        # The JavaScript swallowed this too, so a failed read rendered
        # nothing at all and a story that had run a hundred times looked
        # like a story that had never run.
        return templates.TemplateResponse(
            request=request,
            name=RUNS_FRAGMENT,
            context={"failed": True, "rows": [], "story_id": story_id,
                     "limit": RUNS_LIMIT},
        )

    return templates.TemplateResponse(
        request=request,
        name=RUNS_FRAGMENT,
        context={
            "failed": False,
            "rows": run_rows(payload),
            "story_id": story_id,
            "limit": RUNS_LIMIT,
        },
    )
