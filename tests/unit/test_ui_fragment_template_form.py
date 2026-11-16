"""The template editor as server-rendered fragments.

template_form.html built its section editor in the browser at four
innerHTML sites, across 660 lines of inline JavaScript holding a second
definition of every section type's defaults, of each card's title, of a
variable-name suggester, and of the Jinja2 assembler.

Three things the JavaScript got wrong, which are the substance of this file.

* The form was filled in by script from GET /api/templates/{id} and a
  failed read only raised a toast. The fields stayed empty, Save stayed
  live, and saving an empty editor sends no sections, which the API turns
  into `content: ''` and writes over the stored template body. A read that
  failed could destroy the template it failed to read.
* A failed read and a template that does not exist produced the same toast,
  so "we could not look" and "there is nothing there" were one state.
* Preview assembled its own approximation of fifteen section types, so what
  it showed was not what the save would store. The two already disagree.

Sections are fixtures rather than live data: the dev database's templates
are mostly legacy raw ones, and a render with no sections proves nothing
about a card, which is all that moved.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request

from ion.core.exceptions import TemplateNotFoundError
from ion.services.section_types import SECTION_TYPES, assemble_jinja2
from ion.web.templating import make_templates
from ion.web.ui.template_form import (
    _PERM,
    _field_view,
    apply_edit,
    default_config,
    parse_state,
    router,
    section_title,
    sections_view,
    suggest_variable_name,
)

SECTIONS_FRAGMENT = "_fragments/template_form_sections.html"
FORM_FRAGMENT = "_fragments/template_form.html"
LIBRARY_FRAGMENT = "_fragments/template_form_library.html"
PREVIEW_FRAGMENT = "_fragments/template_form_preview.html"
TEMPLATES = Path(__file__).resolve().parents[2] / "src/ion/web/templates"
PAGE = TEMPLATES / "template_form.html"


def flat(html: str) -> str:
    """Whitespace collapsed, because the template wraps its sentences.

    A prose assertion against the raw render fails on the line break Jinja
    kept, and the obvious fix is to shorten the sentence in the template
    until the test passes, which is the test dictating the wording.
    """
    return re.sub(r"\s+", " ", html)


def render(name: str, **ctx: Any) -> str:
    return make_templates().env.get_template(name).render(**ctx)


def render_sections(sections: list[dict], **over: Any) -> str:
    base = {
        "sections": sections_view(sections),
        "sections_json": json.dumps(sections),
        "legacy": False,
        "edit_failed": False,
        "state_failed": False,
    }
    base.update(over)
    return render(SECTIONS_FRAGMENT, **base)


def render_form(**over: Any) -> str:
    base = {
        "template_id": 4,
        "template": None,
        "sections": [],
        "sections_json": "[]",
        "document_types": {"IR": "Incident Report"},
        "failed": False,
        "not_found": False,
        "legacy": False,
    }
    base.update(over)
    return render(FORM_FRAGMENT, **base)


def heading(**config: Any) -> dict:
    return {"type": "heading", "config": {"text": "Scope", "level": "2", **config}}


# ---------------------------------------------------------------------------
# The cards, which is what the four innerHTML sites built
# ---------------------------------------------------------------------------


def test_a_section_renders_its_title_its_type_and_its_fields():
    """The positive control. Without it every assertion below could pass
    against a fragment that renders nothing at all."""
    html = flat(render_sections([heading()]))
    assert "Scope" in html
    assert "Heading" in html
    assert 'data-field="text"' in html
    assert 'data-field="level"' in html


def test_an_empty_editor_says_so_rather_than_rendering_nothing():
    html = flat(render_sections([]))
    assert "No sections yet" in html


def test_a_select_field_marks_the_stored_value_selected():
    """`level` arrives as the string "2" from the editor and as the number 2
    from a template stored by an older client, and the page compared with
    `String(val) === String(o.value)` for exactly that reason."""
    for stored in ("3", 3):
        html = flat(render_sections([heading(level=stored)]))
        chosen = re.findall(r'<option value="(\d)"[^>]*selected', html)
        assert chosen == ["3"], (stored, chosen)


# ---------------------------------------------------------------------------
# A measured value is not an absent one
# ---------------------------------------------------------------------------


def test_a_declared_default_of_zero_survives_into_the_field():
    """The page wrote `config[f.name] !== undefined ? config[f.name] :
    (f.default || '')`. The first half is right; the second drops a declared
    default of 0 or false, because both are falsy in JavaScript.

    Arranged with 0 rather than None on purpose: None behaves the same under
    every variant of this resolution, so a None-only arrangement would pass
    whatever the code did.
    """
    assert _field_view({"name": "n", "type": "text", "default": 0}, {}, 0)["value"] == "0"
    assert _field_view(
        {"name": "n", "type": "checkbox", "default": False}, {}, 0
    )["checked"] is False
    assert _field_view(
        {"name": "n", "type": "checkbox", "default": True}, {}, 0
    )["checked"] is True


def test_a_stored_value_of_zero_survives_into_the_field():
    assert _field_view({"name": "n", "type": "text"}, {"n": 0}, 0)["value"] == "0"


def test_a_stored_null_renders_an_empty_field_not_the_word_null():
    """`escapeHtml(String(null))` is the four characters "null", which the
    page put in the input for a section whose field was stored as JSON
    null."""
    view = _field_view({"name": "n", "type": "text"}, {"n": None}, 0)
    assert view["value"] == ""


def test_a_table_with_no_columns_says_zero_rather_than_hiding_it():
    """`len(...)`, not truthiness. A table with no columns assembles to
    nothing at all, which is the state most worth seeing on the card."""
    assert section_title(
        {"type": "table", "config": {"columns": []}}, SECTION_TYPES["table"]
    ) == "Table (0 cols)"
    assert section_title(
        {"type": "checklist", "config": {"items": []}}, SECTION_TYPES["checklist"]
    ) == "Checklist (0 items)"


# ---------------------------------------------------------------------------
# The editor's unsaved state survives everything
# ---------------------------------------------------------------------------


def test_the_state_input_is_re_emitted_on_every_branch():
    """A render that dropped it would delete sections the user had written
    and not saved, and the two failure branches are exactly where a
    conversion is tempted to render an error instead of the editor.

    Each branch is arranged with a non-empty state, because an empty one
    renders the same input whatever the code does.
    """
    state = [heading()]
    encoded = json.dumps(state)
    for over in (
        {},
        {"edit_failed": True},
        {"state_failed": True},
    ):
        html = render_sections(state, **over)
        assert 'id="sections-state"' in html, over
        assert encoded.replace('"', "&#34;") in html or encoded.replace(
            '"', "&quot;"
        ) in html, over


def test_a_failed_edit_keeps_the_cards_it_could_not_change():
    html = flat(render_sections([heading()], edit_failed=True))
    assert "That change was not applied" in html
    assert "Scope" in html, "the unsaved section is still on screen"


def test_an_unreadable_state_does_not_offer_an_empty_editor():
    """"No sections yet" next to a state nobody could read invites the user
    to save a template with no sections in it."""
    html = flat(render_sections([], state_failed=True))
    assert "could not be read" in html
    assert "No sections yet" not in html
    assert "saving now would store a template with no sections" in html


# ---------------------------------------------------------------------------
# Escaping, which replaces the page's escapeHtml() calls
# ---------------------------------------------------------------------------


def test_jinja_escapes_what_the_pages_escapehtml_calls_used_to():
    payload = "<script>alert(1)</script>"
    html = render_sections([
        {"type": "text", "config": {"content": payload}},
        {"type": "checklist", "config": {"items": [{"text": payload}]}},
    ])
    assert payload not in html
    assert "&lt;script&gt;" in html


def test_the_state_input_does_not_break_out_of_its_attribute():
    """The state is JSON inside an HTML attribute, which is the one place a
    quote in a user's text could end the attribute early."""
    html = render_sections([{"type": "text", "config": {"content": '"><img src=x>'}}])
    assert "<img src=x>" not in html


# ---------------------------------------------------------------------------
# States the page collapsed
# ---------------------------------------------------------------------------


def test_an_unrecognised_section_type_says_so():
    """The page substituted `{label: type, icon: '?', fields: []}`, which
    renders a card with no controls: indistinguishable from a section that
    has nothing to configure, while still being assembled into the save."""
    html = flat(render_sections([{"type": "not_a_type", "config": {}}]))
    assert "is not in the section library" in html
    assert "not_a_type" in html


def test_a_known_section_type_carries_no_such_warning():
    """The other half of the pair. Without it the assertion above would pass
    for a fragment that warned about every section."""
    assert "is not in the section library" not in flat(render_sections([heading()]))


def test_a_read_that_failed_and_a_template_that_is_absent_read_differently():
    failed = flat(render_form(failed=True))
    missing = flat(render_form(not_found=True))
    assert "could not be read" in failed
    assert "There is no template 4" in missing
    assert "could not be read" not in missing


def test_neither_of_those_states_renders_a_save_button():
    """The defect this conversion exists to remove. The page left Save live
    over an empty form, and the API turns an empty editor into
    `content: ''`, so saving after a failed read overwrites the body."""
    for over in ({"failed": True}, {"not_found": True}):
        html = render_form(**over)
        assert "Save Changes" not in html, over
        assert "Create Template" not in html, over
        assert "<input" not in html, over


def test_a_successful_read_does_render_a_save_button():
    """The positive control for the pair above."""
    html = render_form(template={"name": "N", "format": "markdown",
                                 "document_type": None, "tags": [],
                                 "description": None})
    assert "Save Changes" in html


def test_the_legacy_notice_is_derived_rather_than_switched_off():
    """The page revealed the notice with a style assignment and hid it again
    after converting once, so deleting the converted section left a template
    with an unconverted body and no offer to convert it."""
    assert "Convert to Sections" in flat(render_sections([], legacy=True))
    assert "Convert to Sections" not in flat(render_sections([heading()], legacy=True))
    assert "Convert to Sections" not in flat(render_sections([], legacy=False))


# ---------------------------------------------------------------------------
# The edits, which were six functions in the browser
# ---------------------------------------------------------------------------


def test_add_appends_when_no_position_is_given():
    out = apply_edit([heading()], "add", section_type="divider", insert_at=-1)
    assert [s["type"] for s in out] == ["heading", "divider"]


def test_add_lands_after_the_card_the_button_belongs_to():
    out = apply_edit(
        [heading(), {"type": "divider", "config": {}}],
        "add", section_type="text", insert_at=0,
    )
    assert [s["type"] for s in out] == ["heading", "text", "divider"]


def test_add_gives_the_new_section_the_types_own_defaults():
    out = apply_edit([], "add", section_type="table", insert_at=-1)
    assert out[0]["config"] == default_config(SECTION_TYPES["table"])
    assert out[0]["config"]["columns"] == [{"name": "Column 1"}]


def test_add_refuses_a_type_that_is_not_in_the_library():
    assert apply_edit([], "add", section_type="nope", insert_at=-1) == []


def test_remove_and_move_do_what_the_page_did():
    three = [heading(), {"type": "divider", "config": {}},
             {"type": "text", "config": {}}]
    assert [s["type"] for s in apply_edit(three, "remove", index=1)] == \
        ["heading", "text"]
    assert [s["type"] for s in apply_edit(three, "move", index=0, direction=1)] == \
        ["divider", "heading", "text"]


@pytest.mark.parametrize("index,direction", [(0, -1), (2, 1)])
def test_move_at_the_ends_is_a_no_op(index, direction):
    """The page's `if (newIdx < 0 || newIdx >= sections.length) return;`."""
    three = [heading(), {"type": "divider", "config": {}},
             {"type": "text", "config": {}}]
    assert apply_edit(three, "move", index=index, direction=direction) == three


def test_a_stale_index_is_refused_rather_than_raising():
    """A click lands on markup the next render has already replaced whenever
    two edits are sent quickly, so refusing has to be ordinary."""
    one = [heading()]
    for op in ("remove", "move", "add_item", "remove_item"):
        assert apply_edit(one, op, index=9, direction=1, field="items",
                          list_kind="items", item_index=0) == one, op


@pytest.mark.parametrize("kind,expected", [
    ("items", ""),
    ("checklist", {"text": "", "checked": False}),
    ("pairs", {"label": "", "value": ""}),
    ("columns", {"name": ""}),
    ("metadata", {"label": "", "variable_name": ""}),
    ("signatures", {"role_name": "", "variable_name": ""}),
])
def test_a_new_list_row_has_the_shape_the_page_pushed(kind, expected):
    out = apply_edit(
        [{"type": "checklist", "config": {"items": []}}],
        "add_item", index=0, field="items", list_kind=kind,
    )
    assert out[0]["config"]["items"] == [expected]


def test_removing_a_list_row_removes_that_row():
    out = apply_edit(
        [{"type": "checklist", "config": {"items": ["a", "b", "c"]}}],
        "remove_item", index=0, field="items", item_index=1,
    )
    assert out[0]["config"]["items"] == ["a", "c"]


def test_an_edit_does_not_mutate_the_state_it_was_given():
    """apply_edit is called with the state a failure branch re-emits, so a
    mutation in place would leave the "nothing was lost" message false."""
    state = [heading(), {"type": "divider", "config": {}}]
    before = json.dumps(state)
    apply_edit(state, "remove", index=0)
    apply_edit(state, "move", index=0, direction=1)
    apply_edit(state, "add_item", index=0, field="x", list_kind="items")
    assert json.dumps(state) == before


def test_converting_a_legacy_template_wraps_its_body_in_one_text_section():
    out = apply_edit([], "convert_legacy", legacy_content="# Old body")
    assert out == [{
        "type": "text",
        "config": {"content": "# Old body", "variable": False,
                   "variable_name": ""},
    }]


def test_no_operation_leaves_the_state_alone():
    state = [heading()]
    assert apply_edit(state, None) == state


# ---------------------------------------------------------------------------
# The state that travels
# ---------------------------------------------------------------------------


def test_a_state_that_is_not_a_list_is_an_error_not_an_empty_editor():
    """`json.loads('{}')` succeeds and yields a dict. Accepting it would
    silently empty the editor, which is the one thing a malformed state must
    not be read as."""
    for bad in ("{}", "null", "3", '"x"', "not json at all"):
        with pytest.raises(Exception):
            parse_state(bad)


def test_an_absent_state_is_an_empty_editor():
    assert parse_state(None) == []
    assert parse_state("") == []


def test_a_non_dict_entry_is_dropped_rather_than_crashing_the_render():
    assert parse_state('[{"type": "text"}, 7, null]') == [{"type": "text"}]


# ---------------------------------------------------------------------------
# The suggested variable name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("section,expected", [
    ({"type": "heading", "config": {"text": "Key Findings!"}}, "key_findings"),
    ({"type": "text", "config": {"content": "Some prose here"}}, "some_prose_here"),
    ({"type": "text", "config": {}}, "text"),
    ({"type": "table", "config": {}}, "table"),
])
def test_the_suggested_name_is_the_pages_own_slug(section, expected):
    type_def = SECTION_TYPES.get(section["type"], {})
    assert suggest_variable_name(section, type_def) == expected


def test_the_suggestion_is_rendered_into_the_input_rather_than_added_after():
    """The page rendered the input empty and filled it in from a second pass
    after the render, so for one frame the value the user saw and the value
    the collector read could differ."""
    html = render_sections([
        {"type": "table", "config": {"columns": [{"name": "Host"}],
                                     "variable": True}},
    ])
    assert 'data-field="variable_name"' in html
    assert 'value="table"' in html


def test_a_stored_variable_name_beats_the_suggestion():
    html = render_sections([
        {"type": "table", "config": {"columns": [], "variable": True,
                                     "variable_name": "chosen"}},
    ])
    assert 'value="chosen"' in html
    assert 'value="table"' not in html


# ---------------------------------------------------------------------------
# The routes, which is what selects the states above
# ---------------------------------------------------------------------------


def _request(method: str = "GET", path: str = "/ui/template-form") -> Request:
    return Request({
        "type": "http", "method": method, "path": path, "headers": [],
        "query_string": b"", "scheme": "http", "server": ("testserver", 80),
        "root_path": "",
    })


class _Viewer:
    id = 9

    def has_permission(self, name: str) -> bool:
        return True


def _call_form(monkeypatch, template_id, payload):
    """The route itself, with its one read stubbed.

    The template tests above render each state directly, which proves the
    markup and says nothing about whether the route ever selects it. An
    except handler that rendered the form with empty fields and
    `failed=False` would be exactly the page's defect and would leave every
    template test green.
    """
    from ion.web.ui import template_form as mod

    monkeypatch.setattr(mod, "template_payload", payload)
    return mod.template_form_fragment(
        request=_request(), template_id=template_id, user=_Viewer(),
        services=object(),
    ).body.decode("utf-8")


def test_the_route_renders_the_form_when_the_read_succeeds(monkeypatch):
    html = flat(_call_form(monkeypatch, 4, lambda s, i: {
        "id": 4, "name": "Incident report", "format": "markdown",
        "document_type": None, "description": None, "tags": [],
        "content": "", "sections": [heading()], "has_sections": True,
    }))
    assert "Incident report" in html
    assert "Save Changes" in html
    assert "Scope" in html


def test_the_route_renders_the_failure_state_when_the_read_raises(monkeypatch):
    def boom(services, template_id):
        raise RuntimeError("database gone")

    html = flat(_call_form(monkeypatch, 4, boom))
    assert "could not be read" in html
    assert "Save Changes" not in html


def test_the_route_tells_a_missing_template_from_a_failed_read(monkeypatch):
    def missing(services, template_id):
        raise TemplateNotFoundError("nope")

    html = flat(_call_form(monkeypatch, 4, missing))
    assert "There is no template 4" in html
    assert "could not be read" not in html


def test_the_route_needs_no_read_for_a_new_template(monkeypatch):
    def never(services, template_id):
        raise AssertionError("a new template has nothing to read")

    html = flat(_call_form(monkeypatch, None, never))
    assert "Create Template" in html
    assert "could not be read" not in html


def test_the_route_offers_the_legacy_conversion_on_the_pages_own_condition(
    monkeypatch
):
    html = flat(_call_form(monkeypatch, 4, lambda s, i: {
        "id": 4, "name": "Old", "format": "markdown", "document_type": None,
        "description": None, "tags": [], "content": "# raw body",
        "sections": None, "has_sections": False,
    }))
    assert "Convert to Sections" in html


def test_the_route_does_not_offer_it_for_a_template_that_has_sections(
    monkeypatch
):
    html = flat(_call_form(monkeypatch, 4, lambda s, i: {
        "id": 4, "name": "New", "format": "markdown", "document_type": None,
        "description": None, "tags": [], "content": "# raw body",
        "sections": [heading()], "has_sections": True,
    }))
    assert "Convert to Sections" not in html


def _call_sections(**kwargs):
    from ion.web.ui import template_form as mod

    args = {
        "request": _request("POST", "/ui/template-form/sections"),
        "sections": None, "op": None, "index": None, "section_type": None,
        "insert_at": None, "direction": None, "field": None,
        "list_kind": None, "item_index": None, "template_id": None,
        "legacy": False, "user": _Viewer(), "services": object(),
    }
    args.update(kwargs)
    return mod.template_form_sections_fragment(**args).body.decode("utf-8")


def test_the_sections_route_selects_the_unreadable_state_itself():
    html = flat(_call_sections(sections="{not json"))
    assert "editor state could not be read" in html


def test_the_sections_route_applies_the_edit_it_was_asked_for():
    html = flat(_call_sections(
        sections=json.dumps([heading()]), op="add", section_type="divider",
        insert_at=-1,
    ))
    assert "Horizontal Rule" in html
    assert "Scope" in html


def test_a_convert_with_no_template_id_keeps_the_state_and_says_so():
    """The one edit that needs a read. Without the id there is nothing to
    read, and answering with an empty editor would discard whatever the user
    had already built."""
    state = json.dumps([heading()])
    html = flat(_call_sections(sections=state, op="convert_legacy"))
    assert "That change was not applied" in html
    assert "Scope" in html


def test_a_convert_whose_read_fails_keeps_the_state_and_says_so(monkeypatch):
    from ion.web.ui import template_form as mod

    def boom(services, template_id):
        raise RuntimeError("database gone")

    monkeypatch.setattr(mod, "template_payload", boom)
    html = flat(_call_sections(
        sections=json.dumps([heading()]), op="convert_legacy", template_id=4,
    ))
    assert "That change was not applied" in html
    assert "Scope" in html


def test_a_convert_that_reads_fine_replaces_the_state_with_one_text_section(
    monkeypatch
):
    """The positive control for the two tests above, which would both pass
    for a route that always answered "that change was not applied"."""
    from ion.web.ui import template_form as mod

    monkeypatch.setattr(mod, "template_payload",
                        lambda s, i: {"content": "# raw body"})
    html = flat(_call_sections(sections="[]", op="convert_legacy",
                               template_id=4))
    assert "That change was not applied" not in html
    assert "raw body" in html


# ---------------------------------------------------------------------------
# Preview shows what the save will store
# ---------------------------------------------------------------------------


def _call_preview(sections):
    from ion.web.ui import template_form as mod

    return mod.template_form_preview_fragment(
        request=_request("POST", "/ui/template-form/preview"),
        sections=sections, user=_Viewer(),
    ).body.decode("utf-8")


def test_the_preview_is_the_services_own_assembly():
    """Not an approximation of it. The page's sectionToPreview() was a
    second definition of fifteen section types, and the two already
    disagree: for a variable table the service emits `{{%` where the page's
    preview emitted `{%`.
    """
    state = [heading(), {"type": "table",
                         "config": {"columns": [{"name": "Host"}],
                                    "variable": True,
                                    "variable_name": "rows"}}]
    html = _call_preview(json.dumps(state))
    expected = assemble_jinja2(state)
    assert expected
    # Escaped, because the assembled content is Jinja2 source and has to
    # arrive on screen as those characters.
    assert expected.replace("&", "&amp;").replace("<", "&lt;") in html


def test_a_template_with_no_sections_previews_as_a_stated_emptiness():
    """"" and None are different answers and the route keeps them apart: an
    empty assembly is a real fact about the template, worth knowing before
    saving it."""
    html = flat(_call_preview("[]"))
    assert "would save with no content at all" in html


def test_an_unreadable_state_previews_as_a_failure_not_as_emptiness():
    html = flat(_call_preview("{not json"))
    assert "could not be assembled" in html
    assert "would save with no content at all" not in html


# ---------------------------------------------------------------------------
# Permission, and the payload both pages share
# ---------------------------------------------------------------------------


def _permission_of(route) -> str | None:
    stack, out = list(route.dependant.dependencies), None
    while stack:
        dep = stack.pop()
        fn = dep.call
        if getattr(fn, "__qualname__", "").startswith("require_permission."):
            cells = dict(zip(fn.__code__.co_freevars,
                             (c.cell_contents for c in (fn.__closure__ or ()))))
            out = cells.get("permission_name")
        stack.extend(dep.dependencies)
    return out


def _api_permission(path: str, method: str) -> str | None:
    from ion.web.api import router as api_router

    for route in api_router.routes:
        if route.path == path and method in route.methods:
            return _permission_of(route)
    raise AssertionError(f"no {method} {path} route to read a permission off")


def test_every_fragment_route_carries_the_endpoints_permission():
    """Read off the live routes rather than restated here, so these cannot
    stay on template:read while the API moves."""
    for path in ("/templates/{template_id}", "/templates/section-types"):
        assert _api_permission(path, "GET") == _PERM, path
    assert _api_permission("/document-types", "GET") == _PERM
    assert [_permission_of(r) for r in router.routes] == [_PERM] * 4


def test_the_fragments_are_not_stricter_than_the_api_either():
    """A fragment that copied the save's permission would lock the editor's
    own re-render behind template:update, so a viewer who may read a
    template could not open it."""
    assert _PERM == "template:read"
    assert _api_permission("/templates", "POST") == "template:create"
    assert _api_permission("/templates/{template_id}", "PUT") == "template:update"
    assert _PERM not in ("template:create", "template:update")


def test_the_json_endpoint_and_the_fragments_share_one_payload():
    from ion.web import api
    from ion.web.ui import template_render

    assert hasattr(api, "template_payload")
    assert api.template_payload is not None
    # Both pages read the template through the same function, which is why
    # it was extracted rather than copied into each.
    from ion.web.ui import template_form

    assert template_form.template_payload is api.template_payload
    assert template_render.template_payload is api.template_payload


def test_the_section_type_table_is_the_endpoints_own():
    from ion.web.ui.template_form import _section_types

    assert _section_types() is SECTION_TYPES


# ---------------------------------------------------------------------------
# The page shell
# ---------------------------------------------------------------------------


def _page_js() -> str:
    src = PAGE.read_text(encoding="utf-8")
    return "".join(
        re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S)
    )


def _page_code() -> str:
    """The page's inline JavaScript with its comments removed.

    The comments name the helpers that were deleted and the fetch that no
    longer happens, which is the point of them, so a test for those names
    has to read the code rather than the prose about it.
    """
    return re.sub(r"//[^\n]*", "", _page_js())


def test_the_page_builds_no_markup_in_javascript():
    """The `server` column, measured the way tools/ui_redesign_status.py
    does, and scoped to the inline script: `hx-swap="innerHTML"` is an
    attribute telling htmx where to put server-rendered markup."""
    js = _page_js()
    assert js.strip(), "no inline script found, so this proves nothing"
    assert not re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js
    )


def test_the_page_requests_the_form_on_load():
    src = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="{{ form_url }}"' in src
    assert 'hx-trigger="load"' in src
    assert 'hx-get="/ui/template-form/library"' in src


def test_the_page_carries_no_second_copy_of_the_servers_builders():
    js = _page_code()
    for gone in ("buildFieldsHTML", "buildSingleField", "buildListField",
                 "buildChecklistField", "buildPairsField", "buildColumnsField",
                 "buildMetadataFieldsField", "buildSignatureRolesField",
                 "buildLibrary", "buildDefaultConfig", "getSectionTitle",
                 "suggestVarName", "attachFieldListeners", "sectionToPreview",
                 "renderSections", "escapeHtml"):
        assert gone not in js, gone
    assert "No sections yet" not in js, "the empty state is the server's"


def test_the_page_no_longer_reads_a_preference_key_nothing_writes():
    """The Author prefill read `ion_prefs`. Nothing in the tree has ever
    written that key: the render page's settings modal writes
    `ion_user_prefs`. The prefill could not work and has gone with the
    fetch it rode on. documents.html still reads the dead key, which is
    outside this conversion."""
    js = _page_code()
    assert "ion_prefs" not in js
    assert "localStorage" not in js


def test_the_page_writes_no_htmx_error_handler_of_its_own():
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means, including what an expired session means."""
    src = PAGE.read_text(encoding="utf-8")
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src


def test_the_recovery_controls_sit_outside_every_swap_target():
    """A render that says the read failed must not remove the control that
    retries it, or a page reload is the only way back."""
    src = PAGE.read_text(encoding="utf-8")
    body = src.index('id="template-form-body"')
    assert src.index(">Reload<") > src.index('hx-target="#template-form-body"')
    assert src.index('id="section-library-overlay"') > body
    # The library's Close button is outside the grid that gets swapped.
    assert src.index("se-library-close") < src.index(
        'hx-get="/ui/template-form/library"'
    )


def test_the_add_section_control_sits_outside_the_cards_it_adds_to():
    src = (TEMPLATES / "_fragments/template_form.html").read_text(
        encoding="utf-8"
    )
    assert src.index('data-click-action="openLibrary"') < src.index(
        'id="sections-container"'
    )


@pytest.mark.parametrize("name", [
    "template_form.html",
    "_fragments/template_form.html",
    "_fragments/template_form_sections.html",
    "_fragments/template_form_library.html",
    "_fragments/template_form_preview.html",
])
def test_no_htmx_feature_that_compiles_a_string(name):
    """ION serves script-src with no unsafe-eval, so anything htmx hands to
    Function() throws and the feature silently does nothing. One converted
    page shipped a dead Enter key this way."""
    src = (TEMPLATES / name).read_text(encoding="utf-8")
    assert "hx-on" not in src
    assert "js:" not in src
    assert not re.search(r"hx-trigger=\"[^\"]*\[", src)
    assert not re.search(r"hx-(vals|headers)='\s*js:", src)


def test_a_rejected_save_does_not_re_render_the_form():
    """The one thing a form must not do. A re-render from the server echoes
    back only the fields the server accepted, so a validation failure would
    silently drop the rest of what the user typed. The page's own catch
    raised a toast and left the DOM alone, which was right, and this keeps
    it right.
    """
    js = _page_code()
    catch = js[js.index("} catch (err) {"):]
    assert "showToast" in catch
    assert "htmx" not in catch
    assert "location" not in catch
    assert "template-form-body" not in catch


def test_the_save_is_still_a_mutation_against_the_json_api():
    """Leave the mutations as mutations. What changed is the aftermath."""
    js = _page_code()
    assert "api.put('/api/templates/'" in js
    assert "api.post('/api/templates'" in js


def test_the_editor_state_joins_a_request_in_one_place():
    """A collect call in front of each of the six edits is six places a new
    edit can forget one. Counted: one definition, one guard in the listener,
    and one call in the save."""
    js = _page_code()
    assert js.count("collectSections()") == 3
    assert "htmx:configRequest" in js


def test_the_save_refuses_a_state_it_could_not_read():
    js = _page_code()
    assert "if (sections === null)" in js
