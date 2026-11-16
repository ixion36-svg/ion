"""The Stories page, as four fragments.

What the JavaScript was building, and what each of its claims cost:

  * the rail, whose failure said "Failed to load: <message>" and whose
    empty state said "No stories yet". Both invite someone to create a
    story, and one of them is wrong about whether theirs already exists.
  * the step-type catalogue, whose `catch (e) { }` left the container
    empty, so a failed read read as an executor that supports no steps.
  * the detail editor, whose failed fetch called showToast and left the
    previous story on screen.
  * the run table, whose `catch (e) { }` left it empty too, so a story
    that had failed a hundred times looked like one nobody had run.
  * the validation block, which is not a fragment: it renders a response
    the browser already holds.

Every test here corresponds to a guard that was mutated back to the
defective behaviour and confirmed to turn this file red.
"""
from __future__ import annotations

import json
import logging
import pathlib
import re
from typing import Any

import pytest

from ion.web.templating import make_templates
from ion.web.ui import stories as page

LIST = "_fragments/stories_list.html"
STEP_TYPES = "_fragments/stories_step_types.html"
EDITOR = "_fragments/stories_editor.html"
RUNS = "_fragments/stories_runs.html"

TEMPLATES = pathlib.Path(page.__file__).parent.parent / "templates"
PAGE_HTML = TEMPLATES / "stories.html"


def flat(html: str) -> str:
    """Rendered text with runs of whitespace collapsed.

    Every prose assertion goes through this. The templates wrap their
    sentences to fit the file, so "This is not an empty automation estate"
    arrives with a newline and four spaces inside it and a contiguous
    substring check fails against correct output.
    """
    return " ".join(html.split())


def render(name: str, **ctx: Any) -> str:
    return make_templates().env.get_template(name).render(**ctx)


def render_list(**ctx: Any) -> str:
    ctx.setdefault("failed", False)
    ctx.setdefault("stories", [])
    ctx.setdefault("active_id", None)
    return render(LIST, **ctx)


def render_step_types(**ctx: Any) -> str:
    ctx.setdefault("failed", False)
    ctx.setdefault("step_types", [])
    return render(STEP_TYPES, **ctx)


#: Every button offered, and none, so a test that cares about one
#: permission varies only that one.
ALL_ACTIONS = page.Actions(create=True, update=True, execute=True,
                           delete=True)
NO_ACTIONS = page.Actions(create=False, update=False, execute=False,
                          delete=False)


def render_editor(**ctx: Any) -> str:
    ctx.setdefault("state", "edit")
    ctx.setdefault("story_id", 3)
    ctx.setdefault("story", {"id": 3, "name": "Triage", "description": "",
                             "enabled": True})
    ctx.setdefault("dag_text", "{}")
    ctx.setdefault("can", ALL_ACTIONS)
    return render(EDITOR, **ctx)


def render_runs(**ctx: Any) -> str:
    ctx.setdefault("failed", False)
    ctx.setdefault("rows", [])
    ctx.setdefault("story_id", 3)
    ctx.setdefault("limit", page.RUNS_LIMIT)
    return render(RUNS, **ctx)


def _request():
    from starlette.requests import Request

    return Request({
        "type": "http", "method": "GET", "path": "/ui/stories/list",
        "headers": [], "query_string": b"", "root_path": "",
    })


class _User:
    """A user holding exactly the permissions it was given."""

    def __init__(self, *permissions: str) -> None:
        self._permissions = set(permissions)

    def has_permission(self, name: str) -> bool:
        return name in self._permissions


def _boom(*a: Any, **k: Any):
    raise RuntimeError("database is gone")


def _run(**over: Any) -> dict[str, Any]:
    row = {
        "id": 11, "story_id": 3, "status": "completed", "case_id": 42,
        "alert_id": "alert-1", "triggered_by": 1,
        # Zoneless on purpose. `StoryRun.started_at` is a naive DateTime and
        # story_api._serialise_run emits `.isoformat()`, so this is the only
        # shape the route can produce. An offset-bearing fixture tested the
        # macro's other branch and left this column's rendering unchecked.
        "started_at": "2026-10-12T09:00:00",
        "completed_at": None, "step_outputs": {"note": {"status": "ok"}},
        "error": None,
    }
    row.update(over)
    return row


# ---------------------------------------------------------------------------
# The rail: a failed read is not an empty automation estate
# ---------------------------------------------------------------------------


def test_each_failure_branch_carries_its_own_way_to_retry():
    """A failure state with no control is a dead end when nothing outside it
    re-requests that region. `#story-runs` is triggered only by `load` and
    by a *successful* run, and `#step-types-cat` only by `load`, so a
    failure there could be escaped only by re-requesting the editor, which
    replaces the DAG textarea and discards an unsaved edit."""
    runs = render_runs(failed=True, story_id=4)
    assert 'hx-get="/ui/stories/runs?story_id=4"' in runs
    assert 'hx-target="#story-runs"' in runs
    assert ">Retry</button>" in runs

    cat = render_step_types(failed=True)
    assert 'hx-get="/ui/stories/step-types"' in cat
    assert 'hx-target="#step-types-cat"' in cat
    assert ">Retry</button>" in cat


def test_a_successful_render_offers_no_retry_button():
    """A control that is always there is a control the reader has to decide
    about. These two appear only where the panel cannot recover itself."""
    assert "Retry" not in render_runs(rows=page.run_rows({"runs": [_run()]}))
    assert "Retry" not in render_runs(rows=[])
    assert "Retry" not in render_step_types(
        step_types=[{"type": "x", "label": "y", "description": "z",
                     "config_schema_hint": "{}"}])


def test_a_failed_list_read_does_not_say_no_stories_yet():
    """The two claims lead to opposite actions, and one of them is to write
    a story that already exists."""
    html = render_list(failed=True, stories=[])
    assert "No stories yet" not in html
    assert "not an empty automation estate" in flat(html)


def test_a_successful_empty_list_does_say_no_stories_yet():
    """The other direction. An estate with no stories is a real finding."""
    html = render_list(failed=False, stories=[])
    assert "No stories yet" in html
    assert "not an empty automation estate" not in flat(html)


def test_the_route_renders_the_failure_branch_when_the_list_read_raises(
        monkeypatch):
    """Rendering the template with failed=True proves only that the template
    has a branch. This proves the route picks it."""
    monkeypatch.setattr("ion.web.story_api.list_payload", _boom)
    body = page.stories_list_fragment(_request(), story_id="", session=None).body.decode()
    assert "not an empty automation estate" in flat(body)
    assert "No stories yet" not in body


def test_a_failed_list_read_is_logged_with_its_traceback(monkeypatch, caplog):
    """The fragment answers 200 with honest wording, so the exception is the
    only record that anything broke."""
    monkeypatch.setattr("ion.web.story_api.list_payload", _boom)
    with caplog.at_level(logging.ERROR, logger="ion.web.ui.stories"):
        page.stories_list_fragment(_request(), story_id="", session=None)
    records = [r for r in caplog.records if r.name == "ion.web.ui.stories"]
    assert records, "the failure was swallowed"
    assert all(r.exc_info for r in records), "logged without a traceback"


def test_the_route_renders_the_rows_it_was_given(monkeypatch):
    """Positive control. Without it every assertion above is vacuous."""
    monkeypatch.setattr(
        "ion.web.story_api.list_payload",
        lambda *a, **k: {"stories": [{"id": 4, "name": "Triage",
                                      "enabled": True}], "count": 1},
    )
    body = page.stories_list_fragment(_request(), story_id="", session=None).body.decode()
    assert "Triage" in body
    assert "#4" in body


# ---------------------------------------------------------------------------
# The rail: three states for enabled, and an id of 0 is an id
# ---------------------------------------------------------------------------


def test_an_unknown_enabled_state_is_not_rendered_as_disabled():
    """`enabled` is the only thing on the row that says whether the story can
    run at all. Folding None into "disabled" claims it cannot."""
    html = render_list(stories=[{"id": 1, "name": "A", "enabled": None}])
    assert "state unknown" in html
    assert ">disabled<" not in html


def test_an_enabled_story_says_enabled_and_a_disabled_one_says_disabled():
    on = render_list(stories=[{"id": 1, "name": "A", "enabled": True}])
    off = render_list(stories=[{"id": 1, "name": "A", "enabled": False}])
    assert ">enabled<" in on and "state unknown" not in on
    assert ">disabled<" in off and "state unknown" not in off


def test_story_zero_still_gets_its_number_and_can_be_selected():
    """`is not none`, not truthiness. The id is how a reader refers to the
    story and what the click records as the selection."""
    html = render_list(stories=[{"id": 0, "name": "A", "enabled": True}])
    assert "#0" in html
    assert 'data-story-id="0"' in html
    assert "#?" not in html


def test_a_row_does_not_issue_its_own_request_for_the_pane():
    """It used to carry an hx-get as well as the click action, so one click
    fired the row's request and the pair that `stories:changed` sets off:
    two responses racing onto one target, and two definitions of what
    opening a story does."""
    html = render_list(stories=[{"id": 1, "name": "A", "enabled": True}])
    assert "hx-get" not in html
    assert "hx-target" not in html
    assert 'data-click-action="storiesSelect"' in html


def test_a_story_with_no_id_says_so_rather_than_printing_nothing():
    html = render_list(stories=[{"id": None, "name": "A", "enabled": True}])
    assert "#?" in html


def highlighted(html: str) -> list[str]:
    """The names of the rows carrying the active-row class.

    The class attribute is read as whitespace-separated tokens, because
    `hover:bg-base-300` contains the active class as a substring and a
    substring check would call every row highlighted.
    """
    names = []
    for chunk in html.split("<li")[1:]:
        attrs, _, body = chunk.partition(">")
        classes = attrs.split('class="', 1)[1].split('"', 1)[0].split()
        if "bg-base-300" in classes:
            names.append(body.split("<div")[1].partition(">")[2]
                         .partition("<")[0].strip())
    return names


def test_the_selected_story_is_the_one_highlighted():
    html = render_list(
        stories=[{"id": 1, "name": "A", "enabled": True},
                 {"id": 2, "name": "B", "enabled": True}],
        active_id=2,
    )
    assert highlighted(html) == ["B"]


def test_story_zero_can_be_the_highlighted_one():
    """`is not none`, not truthiness, on both sides of the comparison."""
    html = render_list(stories=[{"id": 0, "name": "A", "enabled": True}],
                       active_id=0)
    assert highlighted(html) == ["A"]


def test_nothing_is_highlighted_when_nothing_is_selected():
    html = render_list(stories=[{"id": 1, "name": "A", "enabled": True}],
                       active_id=None)
    assert highlighted(html) == []


def test_a_story_with_no_id_is_not_highlighted_by_an_empty_selection():
    """None == None is true, so without the `is not none` guard an unsaved
    row would come back highlighted whenever nothing is selected."""
    html = render_list(stories=[{"id": None, "name": "A", "enabled": True}],
                       active_id=None)
    assert highlighted(html) == []


# ---------------------------------------------------------------------------
# The step-type catalogue: the failure the JavaScript swallowed
# ---------------------------------------------------------------------------


def test_a_failed_catalogue_read_does_not_claim_the_executor_supports_nothing():
    html = render_step_types(failed=True, step_types=[])
    assert "reports no step types" not in html
    assert "may still exist" in flat(html)


def test_an_empty_catalogue_that_was_read_says_the_executor_reports_none():
    html = render_step_types(failed=False, step_types=[])
    assert "reports no step types" in html
    assert "may still exist" not in flat(html)


def test_the_catalogue_route_renders_the_failure_branch_when_the_read_raises(
        monkeypatch):
    monkeypatch.setattr("ion.services.story_executor.list_step_types", _boom)
    body = page.stories_step_types_fragment(_request()).body.decode()
    assert "may still exist" in flat(body)
    assert "reports no step types" not in body


def test_the_catalogue_route_renders_the_real_catalogue():
    """Positive control, against the live catalogue rather than a stub."""
    body = page.stories_step_types_fragment(_request()).body.decode()
    assert "case_note" in body
    assert "bob_investigate_alert" in body


def test_a_schema_hint_full_of_braces_is_escaped_not_executed():
    html = render_step_types(step_types=[{
        "type": "x", "label": "y", "description": "z",
        "config_schema_hint": '{"url": "<script>alert(1)</script>"}',
    }])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# The detail pane: five states, and the two the old page did not have
# ---------------------------------------------------------------------------


def test_the_idle_pane_prompts_and_asks_for_the_catalogue():
    html = render_editor(state="idle", story=None)
    assert "Select a story" in flat(html)
    assert 'hx-get="/ui/stories/step-types"' in html
    assert "story-dag" not in html


def test_a_story_that_has_been_deleted_says_so():
    html = render_editor(state="missing", story=None, story_id=9)
    assert "Story #9 no longer exists" in flat(html)
    assert "could not be read" not in html
    assert "story-dag" not in html


def test_a_story_that_could_not_be_read_is_not_a_story_that_was_deleted():
    """The distinction the old page had no way to make. One of these says
    recreate the story and the other says do not."""
    html = render_editor(state="failed", story=None, story_id=9)
    assert "could not be read" in flat(html)
    assert "no longer exists" not in html
    assert "Do not recreate it" in flat(html)


def test_the_route_renders_missing_when_the_story_is_not_there(monkeypatch):
    monkeypatch.setattr("ion.web.story_api.story_payload",
                        lambda *a, **k: None)
    body = page.stories_editor_fragment(
        _request(), story_id="9", mode="", current_user=None, session=None,
    ).body.decode()
    assert "no longer exists" in flat(body)
    assert "could not be read" not in body


def test_the_route_renders_failed_when_the_story_read_raises(monkeypatch):
    monkeypatch.setattr("ion.web.story_api.story_payload", _boom)
    body = page.stories_editor_fragment(
        _request(), story_id="9", mode="", current_user=None, session=None,
    ).body.decode()
    assert "could not be read" in flat(body)
    assert "no longer exists" not in body


def test_a_failed_story_read_is_logged_with_its_traceback(monkeypatch, caplog):
    monkeypatch.setattr("ion.web.story_api.story_payload", _boom)
    with caplog.at_level(logging.ERROR, logger="ion.web.ui.stories"):
        page.stories_editor_fragment(
            _request(), story_id="9", mode="", current_user=None,
            session=None,
        )
    records = [r for r in caplog.records if r.name == "ion.web.ui.stories"]
    assert records and all(r.exc_info for r in records)


def test_the_route_renders_the_story_it_read(monkeypatch):
    """Positive control for the state the pane is in almost all the time.

    Without it a typo in the key the DAG is read from would ship an editor
    showing `{}` for every story, and every other test here would pass."""
    monkeypatch.setattr(
        "ion.web.story_api.story_payload",
        lambda *a, **k: {"id": 7, "name": "Triage", "description": "notes",
                         "enabled": True, "dag_readable": True,
                         "dag": {"start": "note", "nodes": []}},
    )
    body = page.stories_editor_fragment(
        _request(), story_id="7", mode="",
        current_user=_User("playbook:update"), session=None,
    ).body.decode()
    assert 'value="Triage"' in body
    assert "notes" in body
    # Escaped, because it is in the textarea and Jinja autoescapes. The
    # quotes arriving as &#34; is the point: the DAG is data on the page,
    # not markup.
    assert "&#34;start&#34;: &#34;note&#34;" in body
    assert "/ui/stories/runs?story_id=7" in body
    assert "no longer exists" not in body
    assert "could not be read" not in body


def test_the_route_passes_the_selected_id_to_the_payload(monkeypatch):
    seen: dict = {}

    def record(session, story_id):
        seen["story_id"] = story_id
        return None

    monkeypatch.setattr("ion.web.story_api.story_payload", record)
    page.stories_editor_fragment(_request(), story_id=" 7 ", mode="",
                                 current_user=None, session=None)
    assert seen == {"story_id": 7}


def test_an_unreadable_stored_dag_is_not_shown_as_an_empty_story():
    """`_serialise` turns an unparseable dag_json into `{}` and says
    nothing, so the textarea read as a story with no steps."""
    html = render_editor(story={"id": 3, "name": "A", "description": "",
                                "enabled": True, "dag_readable": False},
                         dag_text="{}")
    assert "not valid JSON and could not be read" in flat(html)
    assert "not this story's steps" in flat(html)


def test_a_readable_dag_says_nothing_about_being_unreadable():
    html = render_editor(story={"id": 3, "name": "A", "description": "",
                                "enabled": True, "dag_readable": True})
    assert "not valid JSON" not in html


def test_a_blank_new_story_is_not_accused_of_having_a_broken_dag():
    """`dag_readable` is absent on the blank story, and absent is not a
    claim that the text is broken. `is false`, not truthiness."""
    assert "not valid JSON" not in render_editor(
        state="new", story=page.BLANK_STORY, story_id=None,
        dag_text=page.dag_text(page.BLANK_DAG))


def test_dag_is_readable_tells_corrupt_text_from_an_empty_object():
    from ion.web.story_api import dag_is_readable

    assert dag_is_readable('{"nodes": []}') is True
    assert dag_is_readable("{}") is True
    assert dag_is_readable(None) is True, "an absent DAG is the empty default"
    assert dag_is_readable("{not json") is False


class _Row:
    """The attributes story_api._serialise reads off a Story."""

    def __init__(self, dag_json: str) -> None:
        self.id, self.name, self.description = 3, "A", None
        self.enabled, self.schema_version, self.created_by = True, 1, None
        self.created_at = self.updated_at = None
        self.dag_json = dag_json


class _OneRowSession:
    def __init__(self, row): self._row = row

    def get(self, model, pk): return self._row


@pytest.mark.parametrize("dag_json,readable", [
    ('{"start": "note", "nodes": []}', True),
    ("{}", True),
    ("{not json", False),
    ("", True),
])
def test_story_payload_reports_whether_the_stored_dag_parsed(dag_json,
                                                             readable):
    """Asserted against story_payload itself, not against a stub of it.

    Every other editor test patches story_payload, so a `dag_readable` that
    was hard-coded True would have gone unnoticed: a mutation run proved it
    by doing exactly that and leaving the file green."""
    from ion.web.story_api import story_payload

    payload = story_payload(_OneRowSession(_Row(dag_json)), 3)
    assert payload["dag_readable"] is readable
    assert payload["id"] == 3, "the rest of the payload is unchanged"


def test_story_payload_returns_none_for_a_story_that_is_not_there():
    from ion.web.story_api import story_payload

    assert story_payload(_OneRowSession(None), 3) is None


def test_an_empty_selection_is_the_idle_pane_not_a_rejected_request():
    """The page sends story_id="" with hx-include whenever nothing is
    selected. Declared as an int that is a 422, which htmx renders as a
    server failure when nothing failed."""
    body = page.stories_editor_fragment(
        _request(), story_id="", mode="", current_user=None, session=None,
    ).body.decode()
    assert "Select a story" in flat(body)


def test_a_new_story_starts_from_the_blank_dag(monkeypatch):
    body = page.stories_editor_fragment(
        _request(), story_id="", mode="new",
        current_user=_User("playbook:create"), session=None,
    ).body.decode()
    assert "Create" in body
    assert "{{ trigger.case_id }}" in body
    assert "Hello from a story." in body


def test_the_blank_dag_braces_are_text_and_not_template_syntax():
    """They were wrapped in {% raw %} in the old page because they sat in a
    JavaScript literal inside a Jinja template. As a Python value they are
    just text."""
    assert "{{ trigger.case_id }}" in page.dag_text(page.BLANK_DAG)


def test_a_story_id_wins_over_a_mode_nobody_recognises():
    assert page.detail_state(3, "new") is page.DetailState.EDIT
    assert page.detail_state(None, "nonsense") is page.DetailState.IDLE
    assert page.detail_state(None, "new") is page.DetailState.NEW
    assert page.detail_state(None, "") is page.DetailState.IDLE


@pytest.mark.parametrize("raw,expected", [
    ("", None), ("   ", None), ("7", 7), (" 7 ", 7), ("x", None),
    ("0", 0), (None, None), ("3.5", None),
])
def test_selected_id_parses_the_hidden_input(raw, expected):
    assert page.selected_id(raw) == expected


def test_a_dag_that_will_not_serialise_leaves_an_editable_object():
    class Unserialisable:
        pass

    assert page.dag_text(None) == "{}"
    assert json.loads(page.dag_text({"a": 1})) == {"a": 1}
    # `default=str` catches most of it; the point is that nothing raises
    # through to a 500 that takes the whole pane away.
    assert page.dag_text({"a": Unserialisable()}).startswith("{")


# ---------------------------------------------------------------------------
# The buttons: the page is softer than its own writes
# ---------------------------------------------------------------------------


def test_a_read_only_account_is_offered_no_write_buttons():
    """This page admits any logged-in user while every write is gated, so an
    account with playbook:read alone is real. A Delete button that can only
    answer 403 is a worse answer than no button."""
    html = render_editor(can=NO_ACTIONS)
    assert "storiesSave" not in html
    assert "storiesDelete" not in html
    assert "storiesRun" not in html
    assert "not change or run them" in flat(html)


@pytest.mark.parametrize("action,permission", [
    ("storiesSave", "update"),
    ("storiesRun", "execute"),
    ("storiesDelete", "delete"),
])
def test_each_button_needs_its_own_permission(action, permission):
    assert action not in render_editor(can=NO_ACTIONS)
    assert action in render_editor(
        can=NO_ACTIONS._replace(**{permission: True}))


def test_create_needs_playbook_create_rather_than_update():
    blank = {"id": None, "name": "New story", "description": "",
             "enabled": True}
    no_create = render_editor(state="new", story=blank, story_id=None,
                              can=ALL_ACTIONS._replace(create=False))
    assert ">Create<" not in no_create
    assert "not create them" in flat(no_create)


def test_a_write_permission_is_not_read_off_a_dict_method():
    """Jinja resolves `can.update` as an attribute first, and a dict has an
    `update` method. The method is truthy, so the first version of this
    fragment offered Save to an account with no write permission at all.
    Both halves are asserted, because the fix is only meaningful next to the
    defect it removes."""
    as_dict = {"create": False, "update": False, "execute": False,
               "delete": False}
    assert "storiesSave" in render_editor(can=as_dict), (
        "a dict context still offers Save: that is the trap, not the fix"
    )
    assert "storiesSave" not in render_editor(can=NO_ACTIONS)


def test_allowed_actions_reads_the_permission_each_endpoint_requires():
    assert page.allowed_actions(None) == NO_ACTIONS
    assert page.allowed_actions(_User("playbook:execute")) == \
        NO_ACTIONS._replace(execute=True)
    assert page.allowed_actions(_User("playbook:update")).update is True
    assert page.allowed_actions(_User("playbook:read")) == NO_ACTIONS


# ---------------------------------------------------------------------------
# The run table: a story with no runs is not a story nobody could look at
# ---------------------------------------------------------------------------


def test_a_failed_runs_read_does_not_say_no_runs_yet():
    html = render_runs(failed=True, rows=[])
    assert "No runs yet." not in html
    assert "not a story that has never run" in flat(html)


def test_a_successful_empty_runs_read_does_say_no_runs_yet():
    html = render_runs(failed=False, rows=[])
    assert "No runs yet." in html
    assert "not a story that has never run" not in flat(html)


def test_the_runs_route_renders_the_failure_branch_when_the_read_raises(
        monkeypatch):
    monkeypatch.setattr("ion.web.story_api.runs_payload", _boom)
    body = page.stories_runs_fragment(_request(), story_id=3,
                                      session=None).body.decode()
    assert "not a story that has never run" in flat(body)
    assert "No runs yet." not in body


def test_a_failed_runs_read_is_logged_with_its_traceback(monkeypatch, caplog):
    monkeypatch.setattr("ion.web.story_api.runs_payload", _boom)
    with caplog.at_level(logging.ERROR, logger="ion.web.ui.stories"):
        page.stories_runs_fragment(_request(), story_id=3, session=None)
    records = [r for r in caplog.records if r.name == "ion.web.ui.stories"]
    assert records and all(r.exc_info for r in records)


def test_the_runs_route_asks_for_the_window_the_heading_claims(monkeypatch):
    """`?limit=10` was in the JavaScript. A fragment asking for more would
    make the heading wrong about what it is showing."""
    seen: dict = {}

    def record(session, story_id, *, limit=None):
        seen["limit"] = limit
        seen["story_id"] = story_id
        return {"runs": [], "count": 0}

    monkeypatch.setattr("ion.web.story_api.runs_payload", record)
    page.stories_runs_fragment(_request(), story_id=3, session=None)
    assert seen == {"limit": page.RUNS_LIMIT, "story_id": 3}


def test_a_case_id_of_zero_is_rendered_as_a_case():
    """`r.case_id ? r.case_id : ''` printed a blank for case 0, which reads
    as a run with no case bound at all."""
    html = render_runs(rows=page.run_rows({"runs": [_run(case_id=0)]}))
    assert "<td>0</td>" in html


def test_a_run_with_no_case_renders_an_empty_cell():
    html = render_runs(rows=page.run_rows({"runs": [_run(case_id=None)]}))
    assert "<td>0</td>" not in html
    assert "<td></td>" in html


def test_a_run_id_of_zero_keeps_its_number():
    html = render_runs(rows=page.run_rows({"runs": [_run(id=0)]}))
    assert "#0" in html
    assert "#?" not in html


def test_a_timestamp_goes_through_the_time_macro_not_the_server_clock():
    html = render_runs(rows=page.run_rows({"runs": [_run()]}))
    assert "<time datetime=" in html
    assert "data-ts-format" in html


def test_a_naive_start_time_is_not_moved_to_another_clock():
    """`started_at` is a naive column, so the digits stay as stored and the
    title says whose clock they are on. Localising anyway would shift the
    value by the viewer's offset while looking authoritative."""
    html = render_runs(rows=page.run_rows({"runs": [_run()]}))
    assert 'data-ts-local="no"' in html
    assert "This record stores no timezone" in html


def test_a_run_with_no_start_time_says_so_rather_than_the_epoch():
    html = render_runs(rows=page.run_rows({"runs": [_run(started_at=None)]}))
    assert "no start time" in html
    assert "1970" not in html


@pytest.mark.parametrize("status,badge", [
    # The expected classes are literals, not `page.NEUTRAL_RUN_BADGE`. Read
    # off the module they move with it, so repainting every unknown status
    # the colour of a successful one would leave this green.
    ("completed", "badge-success"),
    ("failed", "badge-error"),
    ("cancelled", "badge-ghost"),
    ("pending", "badge-ghost"),
    ("running", "badge-ghost"),
    (None, "badge-ghost"),
])
def test_every_run_status_maps_to_a_badge(status, badge):
    """The JavaScript's two-way ternary already sent cancelled and pending to
    the neutral badge, so this is the port, not an improvement. A table with
    a default says so in one place."""
    rows = page.run_rows({"runs": [_run(status=status)]})
    assert rows[0]["badge"] == badge


def test_a_run_with_no_recorded_status_says_unrecorded():
    html = render_runs(rows=page.run_rows({"runs": [_run(status=None)]}))
    assert "unrecorded" in html


def test_a_clipped_alert_id_carries_the_whole_value_in_its_title():
    """The JavaScript sliced to 24 and said nothing, so two alerts sharing a
    prefix rendered identically and neither could be copied."""
    long_id = "a" * 40
    rows = page.run_rows({"runs": [_run(alert_id=long_id)]})
    assert rows[0]["alert_id_clipped"] is True
    assert rows[0]["alert_id_short"] == "a" * page.ALERT_ID_CHARS
    html = render_runs(rows=rows)
    assert f'title="{long_id}"' in html
    assert "&hellip;" in html


def test_a_short_alert_id_is_not_marked_as_clipped():
    rows = page.run_rows({"runs": [_run(alert_id="short")]})
    assert rows[0]["alert_id_clipped"] is False
    assert "&hellip;" not in render_runs(rows=rows)


def test_a_run_with_no_alert_renders_no_alert_cell_content():
    rows = page.run_rows({"runs": [_run(alert_id=None)]})
    assert rows[0]["alert_id_short"] is None
    assert "&hellip;" not in render_runs(rows=rows)


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_a_blank_alert_id_is_treated_as_no_alert(blank):
    """An empty string rendered the same empty cell as no alert at all, so
    it read as an id the reader was meant to copy and could not see."""
    rows = page.run_rows({"runs": [_run(alert_id=blank)]})
    assert rows[0]["alert_id"] is None
    assert rows[0]["alert_id_short"] is None
    assert rows[0]["alert_id_clipped"] is False


def test_absent_step_outputs_are_an_empty_object_not_the_word_undefined():
    """`JSON.stringify(undefined, null, 2)` produced the string "undefined"
    in the <pre>, which reads as a captured output whose value is a word."""
    rows = page.run_rows({"runs": [_run(step_outputs=None)]})
    assert rows[0]["step_outputs"] == "{}"
    assert "undefined" not in render_runs(rows=rows)


def test_a_full_table_says_the_count_is_a_floor_and_not_a_total():
    """The JavaScript asked for ?limit=10 and said nothing about it, so a
    reader counting failures read a capped list as the whole history."""
    full = page.run_rows({"runs": [_run(id=i) for i in range(page.RUNS_LIMIT)]})
    short = page.run_rows({"runs": [_run()]})
    assert f"Capped at {page.RUNS_LIMIT}" in flat(render_runs(rows=full))
    assert "Older runs exist" in flat(render_runs(rows=full))
    assert "Capped at" not in flat(render_runs(rows=short))
    assert "Recent runs (1)" in flat(render_runs(rows=short))


# ---------------------------------------------------------------------------
# Escaping, which the hand-rolled esc() used to do
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("html", [
    render_list(stories=[{"id": 1, "name": "<script>alert(1)</script>",
                          "enabled": True}]),
    render_editor(story={"id": 3, "name": "<script>alert(1)</script>",
                         "description": "", "enabled": True}),
    render_runs(rows=page.run_rows(
        {"runs": [_run(error="<script>alert(1)</script>")]})),
])
def test_jinja_escapes_what_the_hand_rolled_esc_used_to(html):
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_a_dag_carrying_a_script_tag_stays_inside_the_textarea():
    html = render_editor(dag_text='{"x": "</textarea><script>alert(1)</script>"}')
    assert "</textarea><script>" not in html
    assert "&lt;/textarea&gt;" in html


# ---------------------------------------------------------------------------
# The permissions, read off the live routes
# ---------------------------------------------------------------------------


def _permissions(route) -> set[str]:
    out, stack = set(), list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        fn = dep.call
        if getattr(fn, "__qualname__", "").startswith("require_permission."):
            cells = dict(zip(fn.__code__.co_freevars,
                             (c.cell_contents for c in (fn.__closure__ or ()))))
            out.add(cells["permission_name"])
        stack.extend(dep.dependencies)
    return out


def test_every_fragment_carries_the_permission_of_the_endpoint_it_mirrors():
    """All four mirror a GET gated on playbook:read. A fragment must never
    be a softer way in than the API it mirrors, and the page's own gate is
    `require_page_auth`, which is softer than all of them."""
    paths = {r.path: _permissions(r) for r in page.router.routes
             if getattr(r, "dependant", None)}
    assert paths == {
        "/stories/list": {page.READ_PERMISSION},
        "/stories/step-types": {page.READ_PERMISSION},
        "/stories/editor": {page.READ_PERMISSION},
        "/stories/runs": {page.READ_PERMISSION},
    }
    assert page.READ_PERMISSION == "playbook:read"


@pytest.mark.parametrize("action,method,path", [
    ("create", "POST", "/api/stories"),
    ("update", "PUT", "/api/stories/{story_id}"),
    ("delete", "DELETE", "/api/stories/{story_id}"),
    ("execute", "POST", "/api/stories/{story_id}/run"),
])
def test_each_button_is_gated_on_the_permission_its_endpoint_requires(
        action, method, path):
    """Read off the live JSON routes, not off a second literal.

    The first version of this compared ACTION_PERMISSIONS to a hand-written
    dict, so it would have stayed green if POST /api/stories had moved to a
    different permission while the Create button quietly disappeared for
    everyone who could still create. That is the one thing on this page a
    diff cannot show."""
    from ion.web.story_api import router as api_router

    route = next(r for r in api_router.routes
                 if getattr(r, "path", None) == path
                 and method in getattr(r, "methods", set()))
    assert _permissions(route) == {page.ACTION_PERMISSIONS[action]}


def test_no_fragment_route_uses_a_redirecting_page_dependency():
    """Covered for every page in test_ui_fragment_registry.py; asserted here
    too because this page's own route uses require_page_auth, so the name is
    one import away."""
    for route in page.router.routes:
        names = []
        stack = list(route.dependant.dependencies)
        while stack:
            dep = stack.pop()
            names.append(getattr(dep.call, "__qualname__", ""))
            stack.extend(dep.dependencies)
        assert not any("require_page" in n for n in names), route.path


# ---------------------------------------------------------------------------
# The page shell
# ---------------------------------------------------------------------------


def _page_text() -> str:
    return PAGE_HTML.read_text(encoding="utf-8")


def _fragment_texts() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8")
            for p in sorted((TEMPLATES / "_fragments").glob("stories*.html"))}


#: What tools/ui_redesign_status.py counts as a runtime markup write. Copied
#: from it rather than approximated, because `hx-swap="innerHTML"` contains
#: the word and is not a write: a looser check here would fail on correct
#: markup and a tighter one would pass a page the tool still fails.
MARKUP_WRITE = re.compile(
    r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?="
)


def test_the_page_and_its_fragments_build_no_markup_in_javascript():
    """The redesign's `server` column. Markup assembled from strings in
    JavaScript cannot be restyled from the stylesheet, so every such site is
    a place a sweep silently fails to reach."""
    sources = {"stories.html": _page_text(), **_fragment_texts()}
    assert len(sources) == 5, sources.keys()
    for name, text in sources.items():
        assert not MARKUP_WRITE.search(text), f"{name} still writes markup"


def test_the_page_uses_no_htmx_feature_that_compiles_a_string():
    """ION serves script-src with no unsafe-eval, so anything htmx hands to
    Function() throws and the feature silently does nothing. One converted
    page shipped a dead Enter key this way."""
    for name, text in {"stories.html": _page_text(),
                       **_fragment_texts()}.items():
        assert "hx-on" not in text, name
        assert "hx-headers" not in text, name
        assert "js:" not in text, name
        assert "[key==" not in text, name
        assert "hx-vals" not in text, name


def test_the_page_writes_no_handler_for_a_failed_fragment_request():
    """static/js/htmx-errors.js is the one definition. A per-page listener
    is one copy per page of what an expired session means."""
    text = _page_text()
    assert "htmx:responseError" not in text
    assert "htmx:sendError" not in text
    assert "htmx:afterSwap" not in text


def test_the_retry_control_is_outside_the_swap_target():
    """A Refresh button inside #stories-list would be removed by the render
    that says the read failed, which is the render that makes someone want
    it."""
    text = _page_text()
    rail = text.split('<ul id="stories-list"')[1].split("</ul>")[0]
    assert "stories-refresh" not in rail
    assert 'id="stories-refresh"' in text
    assert 'hx-target="#stories-list"' in text


def test_the_selection_state_is_outside_both_swap_targets():
    text = _page_text()
    assert 'id="stories-current-id"' in text
    assert 'hx-include="#stories-state"' in text
    rail = text.split('<ul id="stories-list"')[1].split("</ul>")[0]
    pane = text.split('id="story-detail"')[1].split("</main>")[0]
    assert "stories-current-id" not in rail
    assert "stories-current-id" not in pane


def test_the_nested_runs_request_does_not_inherit_the_selection():
    """htmx inherits hx-include, so the runs request inside the pane sent
    the hidden inputs on top of its own URL: `?story_id=1&story_id=1&mode=`.
    Harmless while the two agree, a 422 the moment they do not."""
    text = _page_text()
    pane = text.split('id="story-detail"')[1].split(">")[0]
    assert 'hx-disinherit="hx-include"' in pane
    editor = _fragment_texts()["stories_editor.html"]
    runs_block = editor.split('id="story-runs"')[1].split(">")[0]
    assert "hx-include" not in runs_block


def test_both_panels_load_on_their_own_request():
    text = _page_text()
    assert 'hx-get="/ui/stories/list"' in text
    assert 'hx-get="/ui/stories/editor"' in text
    assert text.count('hx-trigger="load, stories:changed from:body"') == 2


def test_the_run_table_is_refreshed_without_replacing_the_editor():
    """Re-requesting the editor after a run would overwrite the DAG textarea
    and discard an edit that has not been saved."""
    assert "stories:ran" in _page_text()
    editor = _fragment_texts()["stories_editor.html"]
    assert 'hx-trigger="load, stories:ran from:body"' in editor
    # Built as one value with {% set %}, not concatenated in the attribute:
    # `{{ base }}&a={{ b }}` emits an escaped ampersand for the variable and
    # a bare one for the literal.
    assert "'/ui/stories/runs?story_id=' ~ story.id" in editor
    assert 'hx-get="{{ runs_url }}"' in editor


def test_the_validation_block_is_markup_in_the_template_not_in_the_page():
    """It renders a response the browser already holds, so it is not a
    fragment. Its chrome is static markup and the page sets textContent."""
    editor = _fragment_texts()["stories_editor.html"]
    assert "Validation errors" in editor
    assert "data-validation-errors" in editor
    text = _page_text()
    assert "Validation errors" not in text
    assert "textContent" in text


def test_the_hand_rolled_escaper_is_gone():
    assert "function esc(" not in _page_text()


def test_the_page_no_longer_fetches_what_the_fragments_read():
    """The four GETs are gone. The four mutations stay mutations."""
    text = _page_text()
    assert "'/api/stories/step-types'" not in text
    assert "/runs?limit=" not in text
    assert "'/api/stories'" in text, "create still POSTs"
    assert "method: 'DELETE'" in text
