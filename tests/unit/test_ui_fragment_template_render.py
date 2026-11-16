"""The render page as server-rendered fragments.

template_render.html built its variables form, its section cards and its
output pane in the browser at eight innerHTML sites, across 560 lines of
inline JavaScript holding a nine-regex field-type guesser, three option
lists, a 36-word textarea word list, a label formatter and a markdown
section splitter.

Four things the JavaScript got wrong, which are the substance of this file.

* A variable the template declares nothing about and a variable it declares
  as optional rendered identically, because `varMeta[varName] || {}` then
  `if (meta.required)` cannot tell "nobody said" from "not required".
* `renderTemplate()`'s catch wrote the error into the output pane and then
  called `buildSectionCards(splitMarkdownSections(undefined))`, which threw
  inside the catch, so the previous render's section cards stayed on screen
  next to an error about this render.
* `templateInfo` was null until the first load finished and null again if
  that load failed, and `templateInfo && templateInfo.format === 'markdown'`
  then chose the preformatted output branch for a markdown template.
* Save as Document was offered to every viewer, including one holding no
  document:create, so the only way to learn the server would refuse was to
  name a document and click.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request

from ion.core.exceptions import RenderError, TemplateNotFoundError
from ion.web.templating import make_templates
from ion.web.ui.template_render import (
    _PERM,
    _SAVE_PERM,
    field_kind,
    format_label,
    router,
    split_sections,
    variable_view,
    variables_view,
)

VARIABLES_FRAGMENT = "_fragments/template_render_variables.html"
SECTIONS_FRAGMENT = "_fragments/template_render_sections.html"
OUTPUT_FRAGMENT = "_fragments/template_render_output.html"
TEMPLATES = Path(__file__).resolve().parents[2] / "src/ion/web/templates"
PAGE = TEMPLATES / "template_render.html"

TODAY = "2026-10-12"


def flat(html: str) -> str:
    """Whitespace collapsed, because the template wraps its sentences.

    A prose assertion against the raw render fails on the line break Jinja
    kept, and the obvious fix is to shorten the sentence in the template
    until the test passes, which is the test dictating the wording.
    """
    return re.sub(r"\s+", " ", html)


def render(fragment: str, **ctx: Any) -> str:
    return make_templates().env.get_template(fragment).render(**ctx)


def render_variables(**over: Any) -> str:
    base = {
        "template_id": 3,
        "name": "Incident report",
        "format": "markdown",
        "variables": {"fields": [], "undescribed": 0, "total": 0},
        "failed": False,
        "not_found": False,
        "can_save": True,
    }
    base.update(over)
    return render(VARIABLES_FRAGMENT, **base)


def render_sections(**over: Any) -> str:
    base = {
        "sections": None, "failed": False, "not_found": False,
        "data_invalid": False, "render_error": None,
    }
    base.update(over)
    return render(SECTIONS_FRAGMENT, **base)


def render_output(**over: Any) -> str:
    base = {
        "template_id": 3, "rendered": None, "format": None, "failed": False,
        "not_found": False, "data_invalid": False, "render_error": None,
        "sections": None,
    }
    base.update(over)
    return render(OUTPUT_FRAGMENT, **base)


def payload(extracted: list[str], defined: list[dict] | None = None) -> dict:
    return {"extracted": extracted, "defined": defined or []}


def output_pane(html: str) -> str:
    """Just the output pane, without the section cards swapped out of band.

    The cards carry markdown panes of their own, so an assertion that the
    output pane is NOT a markdown pane matches one of theirs and passes
    whatever the output branch did.
    """
    marker = '<div id="section-cards"'
    return html.split(marker)[0]


# ---------------------------------------------------------------------------
# The variables form, which was two of the eight innerHTML sites
# ---------------------------------------------------------------------------


def test_a_variable_renders_a_labelled_input():
    """The positive control. Without it every assertion below could pass
    against a fragment that renders nothing at all."""
    view = variables_view(payload(["prepared_by"]))
    html = flat(render_variables(variables=view))
    assert "Prepared By" in html
    assert 'name="prepared_by"' in html
    assert 'id="var-prepared_by"' in html


def test_a_template_with_no_variables_says_so():
    html = flat(render_variables(variables={"fields": [], "undescribed": 0,
                                            "total": 0}))
    assert "This template has no variables" in html


@pytest.mark.parametrize("name,expected", [
    ("date", "date"),
    ("assessment_date", "date"),
    ("review_date", "date"),
    ("version", "version"),
    ("schema_version", "version"),
    ("prepared_by", "author"),
    ("classification", "classification"),
    ("severity", "severity"),
    ("host_count", "number"),
    ("num_alerts", "number"),
    ("review_cycle", "review_cycle"),
    ("findings", "textarea"),
    ("executive_summary", "textarea"),
    ("widget", "text"),
])
def test_the_field_kind_is_the_pages_own_guess(name, expected):
    """Lifted verbatim, so a variable that got a date picker still gets one.
    The order matters: `assessment_date` must match the date rule before the
    textarea word list catches "assessment"."""
    assert field_kind(name)["kind"] == expected


@pytest.mark.parametrize("name,expected", [
    ("prepared_by", "Prepared By"),
    ("assessmentDate", "Assessment Date"),
    ("date", "Date"),
])
def test_the_label_is_the_pages_own_format(name, expected):
    assert format_label(name) == expected


# ---------------------------------------------------------------------------
# Three states the page had two of
# ---------------------------------------------------------------------------


def test_a_declared_required_variable_is_marked_required():
    view = variables_view(payload(
        ["widget"], [{"name": "widget", "required": True}]
    ))
    assert view["fields"][0]["required"] is True
    html = flat(render_variables(variables=view))
    assert 'class="required"' in html
    assert ">optional<" not in html


def test_a_declared_optional_variable_says_optional():
    """The middle branch, and the one a mutation has to delete to break
    this. Weakening the first condition to truthiness changes nothing while
    `is false` still catches the undeclared case."""
    view = variables_view(payload(
        ["widget"], [{"name": "widget", "required": False}]
    ))
    assert view["fields"][0]["required"] is False
    html = flat(render_variables(variables=view))
    assert ">optional<" in html
    assert 'class="required"' not in html


def test_an_undeclared_variable_is_neither_required_nor_optional():
    """The page did `varMeta[varName] || {}` and then `if (meta.required)`,
    so a variable the template says nothing about rendered exactly like one
    it declares as not required.

    Arranged with a declared variable alongside, because None behaves
    identically under `is true`, truthiness and `is not None`: an
    arrangement holding only the undeclared case would pass whatever the
    code did.
    """
    view = variables_view(payload(
        ["widget", "gadget"], [{"name": "widget", "required": False}]
    ))
    kinds = {f["name"]: f["required"] for f in view["fields"]}
    assert kinds == {"widget": False, "gadget": None}
    html = flat(render_variables(variables=view))
    assert html.count(">optional<") == 1, "only the declared one is optional"
    assert 'class="required"' not in html


def test_the_form_says_how_many_of_its_fields_were_guessed_at():
    view = variables_view(payload(
        ["widget", "gadget"], [{"name": "widget", "required": True}]
    ))
    assert view["undescribed"] == 1
    assert view["total"] == 2
    html = flat(render_variables(variables=view))
    assert "1 of these 2 fields are used by the template but not declared" in html


def test_a_fully_declared_form_says_nothing_about_guessing():
    """`is not none and > 0`, never truthiness. Zero undescribed variables
    is the good news the line exists to deliver, and a truthiness test
    renders that case identically to never having counted."""
    view = variables_view(payload(
        ["widget"], [{"name": "widget", "required": True}]
    ))
    assert view["undescribed"] == 0
    assert "not declared by it" not in flat(render_variables(variables=view))


# ---------------------------------------------------------------------------
# Defaults, computed once and carried with the field
# ---------------------------------------------------------------------------


def test_a_date_field_defaults_to_the_same_utc_day_the_page_used():
    """`new Date().toISOString().split('T')[0]` is UTC, so this is the same
    date the page filled in rather than the server's local one. A date
    rendered from the server's own clock would be a day out for half the
    world, which is the timestamp mistake in another costume."""
    view = variable_view("report_date", None, TODAY)
    assert view["default"] == TODAY


def test_the_static_defaults_are_the_pages_own():
    assert variable_view("version", None, TODAY)["default"] == "1.0"
    assert variable_view("review_cycle", None, TODAY)["default"] == "Annual"


def test_the_author_and_classification_defaults_are_left_to_the_browser():
    """They are the viewer's own stored preferences and never leave the
    browser, so the server renders no value rather than guessing one."""
    assert variable_view("author", None, TODAY)["default"] is None
    assert variable_view("classification", None, TODAY)["default"] is None
    assert variable_view("author", None, TODAY)["auto_fill"] is True


def test_a_declared_default_beats_the_guessed_one():
    view = variable_view(
        "report_date", {"required": True, "default_value": "2020-01-01"}, TODAY
    )
    assert view["default"] == "2020-01-01"


def test_the_rendered_value_and_the_autofill_default_are_the_same_value():
    """The page recomputed the default inside autoFillDefaults from a second
    call to detectFieldType, so the button and the first paint were two
    chances to disagree."""
    view = variables_view(payload(["report_date"]))
    html = render_variables(variables=view)
    rendered = re.search(r'value="([^"]*)"[^>]*data-autofill-default="([^"]*)"',
                         flat(html))
    assert rendered, html
    assert rendered.group(1) == rendered.group(2)


def test_a_declared_option_list_beats_the_guess_from_the_name():
    """The template says what the values are, so the variable's name no
    longer has to be read."""
    view = variable_view(
        "severity", {"required": True, "options": ["P1", "P2"]}, TODAY
    )
    assert view["input"] == "options"
    assert view["options"] == ["P1", "P2"]
    html = flat(render_variables(
        variables={"fields": [view], "undescribed": 0, "total": 1}
    ))
    assert "P1" in html
    assert "Critical" not in html, "the guessed severity list is not used"


def test_the_guessed_option_lists_are_the_pages_own():
    assert variable_view("classification", None, TODAY)["options"][0] == \
        "UNCLASSIFIED"
    assert variable_view("severity", None, TODAY)["options"] == [
        "Critical", "High", "Medium", "Low", "Informational"
    ]


# ---------------------------------------------------------------------------
# Escaping, which replaces the page's escapeHtml() calls
# ---------------------------------------------------------------------------


def test_jinja_escapes_what_the_pages_escapehtml_calls_used_to():
    payload_text = "<script>alert(1)</script>"
    html = render_variables(name=payload_text, variables=variables_view(
        payload([payload_text])
    ))
    assert payload_text not in html
    assert "&lt;script&gt;" in html


def test_the_section_markdown_arrives_as_text_not_as_markup():
    """The markdown goes into a textarea and the browser's own sanitiser
    paints it. A tag reaching the page as markup would be the one thing
    moving the render server-side must not do."""
    sections = split_sections("## 1. Scope\n<script>alert(1)</script>")
    html = render_sections(sections=sections)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_the_output_markdown_arrives_as_text_too():
    html = render_output(rendered="<script>alert(1)</script>",
                         format="markdown", sections=[])
    assert "<script>alert(1)</script>" not in html


# ---------------------------------------------------------------------------
# Splitting the rendered document
# ---------------------------------------------------------------------------


def test_the_document_splits_on_its_numbered_headings():
    out = split_sections("preamble\n\n## 1. Scope\nbody\n\n## 2. Findings\nmore")
    assert [(s["idx"], s["label"], s["title"]) for s in out] == [
        (0, "HDR", "Document Header"),
        (1, "S1", "Scope"),
        (2, "S2", "Findings"),
    ]


def test_the_header_part_opens_and_the_numbered_ones_do_not():
    out = split_sections("preamble\n\n## 1. Scope\nbody")
    assert [s["is_header"] for s in out] == [True, False]
    html = render_sections(sections=out)
    assert html.count("se-card se-open") == 1


def test_an_empty_part_is_dropped_without_leaving_a_gap_in_the_indexes():
    """The index is what the save reassembles in, so numbering before the
    filter would leave a gap and the assembled document would be short a
    section."""
    out = split_sections("\n\n## 1. Scope\nbody\n\n## 2. Next\nmore")
    assert [s["idx"] for s in out] == [0, 1]
    assert [s["title"] for s in out] == ["Scope", "Next"]


def test_nothing_rendered_and_an_empty_render_are_both_empty_lists():
    assert split_sections(None) == []
    assert split_sections("") == []


def test_a_document_that_rendered_to_nothing_says_that_rather_than_failing():
    html = flat(render_sections(sections=[]))
    assert "rendered to an empty document" in html
    assert "could not be read" not in html


# ---------------------------------------------------------------------------
# Four reasons there are no sections, which the page had one of
# ---------------------------------------------------------------------------


def test_each_failure_reads_differently_from_the_others():
    states = {
        "data_invalid": "not valid JSON",
        "not_found": "no longer exists",
        "render_error": "could not be rendered with this data",
        "failed": "sections could not be read",
    }
    for flag, phrase in states.items():
        value = "x is undefined" if flag == "render_error" else True
        html = flat(render_sections(**{flag: value}))
        assert phrase in html, flag
        for other, other_phrase in states.items():
            if other != flag:
                assert other_phrase not in html, (flag, other)


def test_a_render_error_names_the_expression_that_stopped_it():
    """The template's own message is better than anything restated: it names
    the variable or the expression."""
    html = flat(render_sections(render_error="customer is undefined"))
    assert "customer is undefined" in html


def test_no_render_requested_is_not_a_document_with_no_sections():
    html = flat(render_sections(sections=None))
    assert "No render has been requested yet" in html
    assert "rendered to an empty document" not in html


# ---------------------------------------------------------------------------
# The output pane
# ---------------------------------------------------------------------------


def test_a_markdown_template_is_painted_and_anything_else_is_preformatted():
    md = output_pane(render_output(rendered="# Title", format="markdown",
                                   sections=[]))
    assert "data-md-pane" in md
    assert "rendered-output" not in md

    txt = output_pane(render_output(rendered="plain", format="text",
                                    sections=[]))
    assert "rendered-output" in txt
    assert "data-md-pane" not in txt


def test_a_template_that_rendered_to_an_empty_string_has_still_rendered():
    """`is not none`, not truthiness. Showing the "click Preview" prompt for
    an empty render would say no render had happened."""
    html = flat(output_pane(render_output(rendered="", format="markdown",
                                          sections=[])))
    assert 'Fill in the fields and click "Preview"' not in html
    assert "data-md-pane" in html


def test_nothing_rendered_yet_shows_the_prompt():
    html = flat(render_output(rendered=None, format="markdown"))
    assert 'Fill in the fields and click "Preview"' in html


def test_the_output_always_replaces_the_section_cards_with_it():
    """The page's catch wrote an error into the output pane and then threw
    inside the catch while rebuilding the cards, leaving the previous
    render's sections next to an error about this one. Every branch carries
    the out-of-band swap, so that cannot happen."""
    for over in (
        {"rendered": "# ok", "format": "markdown", "sections": []},
        {"failed": True},
        {"data_invalid": True},
        {"render_error": "boom"},
        {"not_found": True},
        {"rendered": None, "format": "markdown"},
    ):
        html = render_output(**over)
        assert 'id="section-cards" hx-swap-oob="innerHTML"' in html, over


def test_the_out_of_band_swap_keeps_the_loader_on_the_element():
    """An outerHTML swap would replace `#section-cards` with the response's
    copy and take the hx-post that loads it on page load with it."""
    html = render_output(rendered="# ok", format="markdown", sections=[])
    assert 'hx-swap-oob="innerHTML"' in html
    assert 'hx-swap-oob="true"' not in html


# ---------------------------------------------------------------------------
# The routes, which is what selects the states above
# ---------------------------------------------------------------------------


def _request(method: str = "GET", path: str = "/ui/template-render") -> Request:
    return Request({
        "type": "http", "method": method, "path": path, "headers": [],
        "query_string": b"", "scheme": "http", "server": ("testserver", 80),
        "root_path": "",
    })


class _Viewer:
    id = 9

    def __init__(self, can_save: bool = True) -> None:
        self._can_save = can_save

    def has_permission(self, name: str) -> bool:
        if name == _SAVE_PERM:
            return self._can_save
        return True


def _call_variables(monkeypatch, *, info=None, variables=None,
                    can_save: bool = True):
    """The route itself, with both reads stubbed.

    The template tests above render each state directly, which proves the
    markup and says nothing about whether the route ever selects it. An
    except handler that rendered an empty form with `failed=False` would be
    the page's own defect and would leave every template test green.
    """
    from ion.web.ui import template_render as mod

    monkeypatch.setattr(mod, "template_payload", info or (
        lambda s, i: {"name": "Incident report", "format": "markdown"}
    ))
    monkeypatch.setattr(mod, "template_variables_payload", variables or (
        lambda s, i: payload(["widget"])
    ))
    return mod.template_render_variables_fragment(
        request=_request(), template_id=3, user=_Viewer(can_save),
        services=object(),
    ).body.decode("utf-8")


def test_the_variables_route_renders_the_form_when_both_reads_succeed(
    monkeypatch
):
    html = flat(_call_variables(monkeypatch))
    assert "Incident report" in html
    assert 'name="widget"' in html


def test_the_variables_route_renders_the_failure_state_when_a_read_raises(
    monkeypatch
):
    def boom(services, template_id):
        raise RuntimeError("database gone")

    html = flat(_call_variables(monkeypatch, info=boom))
    assert "could not be read" in html
    assert "saveAsDocument" not in html


def test_the_variables_route_tells_a_missing_template_from_a_failed_read(
    monkeypatch
):
    def missing(services, template_id):
        raise TemplateNotFoundError("nope")

    html = flat(_call_variables(monkeypatch, info=missing))
    assert "There is no template 3" in html
    assert "could not be read" not in html


def test_the_second_read_failing_is_also_a_failure_not_an_empty_form(
    monkeypatch
):
    """Arranged separately from the first, because a route that only wrapped
    one of its two reads would leave the other raising a 500 and the test
    above green."""
    def boom(services, template_id):
        raise RuntimeError("renderer gone")

    html = flat(_call_variables(monkeypatch, variables=boom))
    assert "could not be read" in html
    assert "This template has no variables" not in html


def test_the_heading_is_told_the_truth_on_every_branch(monkeypatch):
    """The page left the heading reading "Loading..." for ever when the load
    failed."""
    def boom(services, template_id):
        raise RuntimeError("database gone")

    def missing(services, template_id):
        raise TemplateNotFoundError("nope")

    assert 'id="template-name" hx-swap-oob="true">could not be read<' in \
        _call_variables(monkeypatch, info=boom)
    assert 'id="template-name" hx-swap-oob="true">no such template<' in \
        _call_variables(monkeypatch, info=missing)
    assert 'id="template-name" hx-swap-oob="true">Incident report<' in \
        _call_variables(monkeypatch)


def test_save_as_document_is_withheld_from_a_viewer_who_cannot_create_one(
    monkeypatch
):
    """The page offered it to everyone and let POST /api/templates/{id}/render
    answer 403, so the only way to find out was to name a document and
    click."""
    held = _call_variables(monkeypatch, can_save=True)
    withheld = _call_variables(monkeypatch, can_save=False)
    assert "saveAsDocument" in held
    assert "saveAsDocument" not in withheld
    assert "document:create" in flat(withheld)


def _call_sections(monkeypatch, *, preview=None, data_json="{}"):
    from ion.web.ui import template_render as mod

    monkeypatch.setattr(mod, "_preview", preview or (
        lambda s, i, d: "## 1. Scope\nbody"
    ))
    return mod.template_render_sections_fragment(
        request=_request("POST", "/ui/template-render/sections"),
        template_id=3, data_json=data_json, user=_Viewer(),
        services=object(),
    ).body.decode("utf-8")


def test_the_sections_route_renders_the_cards_when_the_preview_succeeds(
    monkeypatch
):
    html = flat(_call_sections(monkeypatch))
    assert "Scope" in html
    assert "could not be read" not in html


def test_the_sections_route_selects_the_render_error_state_itself(monkeypatch):
    def boom(services, template_id, data):
        raise RenderError("customer is undefined")

    html = flat(_call_sections(monkeypatch, preview=boom))
    assert "could not be rendered with this data" in html
    assert "customer is undefined" in html


def test_the_sections_route_selects_the_failed_state_for_anything_else(
    monkeypatch
):
    def boom(services, template_id, data):
        raise RuntimeError("database gone")

    html = flat(_call_sections(monkeypatch, preview=boom))
    assert "sections could not be read" in html


def test_the_sections_route_selects_the_bad_data_state_itself(monkeypatch):
    def never(services, template_id, data):
        raise AssertionError("the data never parsed, so nothing to render")

    html = flat(_call_sections(monkeypatch, preview=never,
                               data_json="{not json"))
    assert "not valid JSON" in html


def test_data_that_is_not_an_object_is_refused(monkeypatch):
    """`json.loads('[]')` succeeds and yields a list, which the renderer
    cannot use as a variable mapping."""
    def never(services, template_id, data):
        raise AssertionError("a list is not a variable mapping")

    html = flat(_call_sections(monkeypatch, preview=never, data_json="[]"))
    assert "not valid JSON" in html


def _call_output(monkeypatch, *, info=None, preview=None, data_json="{}",
                 content=None):
    from ion.web.ui import template_render as mod

    monkeypatch.setattr(mod, "template_payload", info or (
        lambda s, i: {"name": "N", "format": "markdown"}
    ))
    monkeypatch.setattr(mod, "_preview", preview or (
        lambda s, i, d: "## 1. Scope\nbody"
    ))
    return mod.template_render_output_fragment(
        request=_request("POST", "/ui/template-render/output"),
        template_id=3, data_json=data_json, content=content, user=_Viewer(),
        services=object(),
    ).body.decode("utf-8")


def test_the_output_route_previews_when_it_is_given_no_content(monkeypatch):
    html = _call_output(monkeypatch)
    assert "Scope" in html
    assert 'data-md-pane' in html


def test_the_output_route_shows_the_saved_content_rather_than_re_previewing(
    monkeypatch
):
    """Save as Document has already stored the document, including the
    section edits. A fresh preview would re-render from the template and
    silently drop them."""
    def never(services, template_id, data):
        raise AssertionError("a save must not be re-previewed")

    html = _call_output(monkeypatch, preview=never,
                        content="## 1. Edited scope\nmine")
    assert "Edited scope" in html


def test_an_empty_saved_content_is_still_content_not_an_absent_render(
    monkeypatch
):
    """`content is not None`, never truthiness: a document saved empty has
    been saved, and falling through to the preview would re-render the
    template and show something that was never stored.

    The preview is stubbed to return a recognisable string rather than to
    raise. A raising stub made this test vacuous: the truthiness mutation
    fell through to the preview, the raise was caught by the route's own
    except handler, and the failure branch it rendered is also missing the
    "click Preview" prompt this used to assert the absence of. A mutation
    pass is what showed it.
    """
    html = output_pane(_call_output(
        monkeypatch, preview=lambda s, i, d: "## 1. A fresh preview",
        content="",
    ))
    assert "A fresh preview" not in html, "an empty save was re-previewed"
    assert "data-md-pane" in html, "an empty save is still a rendered document"
    assert "could not be read" not in flat(html)


def test_the_output_route_reads_the_format_from_the_template(monkeypatch):
    """The page read it off a `templateInfo` variable that was null until
    the first load finished and null again if it failed, and then chose the
    preformatted branch for a markdown template."""
    html = output_pane(_call_output(
        monkeypatch, info=lambda s, i: {"name": "N", "format": "text"}
    ))
    assert "rendered-output" in html
    assert "data-md-pane" not in html


def test_the_output_route_selects_each_failure_state_itself(monkeypatch):
    def render_boom(services, template_id, data):
        raise RenderError("x is undefined")

    def read_boom(services, template_id, data):
        raise RuntimeError("database gone")

    assert "x is undefined" in flat(
        _call_output(monkeypatch, preview=render_boom))
    assert "could not be read" in flat(
        _call_output(monkeypatch, preview=read_boom))
    assert "not valid JSON" in flat(
        _call_output(monkeypatch, data_json="{nope"))

    def info_boom(services, template_id):
        raise TemplateNotFoundError("nope")

    assert "no longer exists" in flat(_call_output(monkeypatch, info=info_boom))


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


def test_every_fragment_route_carries_the_endpoints_read_permission():
    """Read off the live routes rather than restated here."""
    for path, method in (
        ("/templates/{template_id}", "GET"),
        ("/templates/{template_id}/variables", "GET"),
        ("/templates/{template_id}/preview", "POST"),
    ):
        assert _api_permission(path, method) == _PERM, (path, method)
    assert [_permission_of(r) for r in router.routes] == [_PERM] * 3


def test_the_save_permission_is_the_one_the_save_endpoint_takes():
    """The button this fragment withholds is withheld on the permission the
    server would really check, not on a guess."""
    assert _api_permission("/templates/{template_id}/render", "POST") == \
        _SAVE_PERM
    assert _SAVE_PERM == "document:create"
    assert _PERM != _SAVE_PERM


def test_the_page_is_gated_more_loosely_than_its_own_save():
    """Stated rather than changed. GET /templates/{id}/render is gated on
    template:read, so a viewer who may read a template reaches this page and
    cannot save a document from it. The fragment matches the read it mirrors
    and withholds the button instead."""
    from ion.web.server import app

    # The page uses require_page_permission, whose closure cell holds the
    # name, so it is read the same way but not by _permission_of, which
    # deliberately only recognises the API factory.
    gates = []
    for route in app.routes:
        if getattr(route, "path", None) != "/templates/{template_id}/render":
            continue
        stack = list(route.dependant.dependencies)
        while stack:
            dep = stack.pop()
            fn = dep.call
            if getattr(fn, "__qualname__", "").startswith(
                "require_page_permission."
            ):
                cells = dict(zip(
                    fn.__code__.co_freevars,
                    (c.cell_contents for c in (fn.__closure__ or ())),
                ))
                gates.append(cells.get("permission_name"))
            stack.extend(dep.dependencies)
    assert gates == ["template:read"], gates
    assert _SAVE_PERM not in gates


def test_the_preview_goes_through_the_service_the_endpoint_calls():
    import inspect

    from ion.web.ui import template_render as mod

    source = inspect.getsource(mod._preview)
    assert "services.render.preview" in source


def test_both_payloads_are_the_endpoints_own():
    from ion.web import api
    from ion.web.ui import template_render as mod

    assert mod.template_payload is api.template_payload
    assert mod.template_variables_payload is api.template_variables_payload


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

    The comments name the helpers that were deleted and the markup that is
    no longer built, which is the point of them, so a test for those names
    has to read the code rather than the prose about it.
    """
    return re.sub(r"//[^\n]*", "", _page_js())


def test_the_page_builds_no_markup_in_javascript():
    """The `server` column, measured the way tools/ui_redesign_status.py
    does, and scoped to the inline script."""
    js = _page_js()
    assert js.strip(), "no inline script found, so this proves nothing"
    assert not re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js
    )


def test_the_page_carries_no_second_copy_of_the_servers_builders():
    js = _page_code()
    for gone in ("buildVariablesForm", "buildInputForField",
                 "buildOptionsSelect", "buildSelectField", "detectFieldType",
                 "shouldUseTextarea", "formatLabel", "splitMarkdownSections",
                 "buildSectionCards", "escapeHtml", "renderTemplate",
                 "loadSections"):
        assert gone not in js, gone
    assert "UNCLASSIFIED" not in js, "the option lists are the server's"
    assert "has no variables" not in js, "the empty state is the server's"


def test_the_page_requests_its_three_fragments():
    src = PAGE.read_text(encoding="utf-8")
    assert 'hx-get="/ui/template-render/variables?template_id={{ template_id }}"' in src
    assert 'hx-post="/ui/template-render/sections"' in src
    assert 'hx-trigger="load"' in src


def test_the_first_section_render_waits_for_the_form_it_renders_from():
    """Two independent `load` triggers race, and the sections have to be
    rendered from the values the form was filled in with."""
    src = PAGE.read_text(encoding="utf-8")
    assert 'hx-trigger="variablesReady"' in src
    js = _page_code()
    assert "htmx.trigger('#section-cards', 'variablesReady')" in js


def test_the_page_writes_no_htmx_error_handler_of_its_own():
    src = PAGE.read_text(encoding="utf-8")
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src


def test_the_recovery_controls_sit_outside_every_swap_target():
    src = PAGE.read_text(encoding="utf-8")
    assert src.index(">Reload<") < src.index('id="variables-form"')
    assert src.index("expand-all-btn") < src.index('id="section-cards"')
    assert src.index("collapse-all-btn") < src.index('id="section-cards"')


@pytest.mark.parametrize("name", [
    "template_render.html",
    "_fragments/template_render_variables.html",
    "_fragments/template_render_sections.html",
    "_fragments/template_render_output.html",
])
def test_no_htmx_feature_that_compiles_a_string(name):
    """ION serves script-src with no unsafe-eval, so anything htmx hands to
    Function() throws and the feature silently does nothing. One converted
    page shipped a dead Enter key this way."""
    src = (TEMPLATES / name).read_text(encoding="utf-8")
    assert "hx-on" not in src
    assert not re.search(r"hx-trigger=\"[^\"]*\[", src)
    assert not re.search(r"hx-(vals|headers)='\s*js:", src)


def test_the_save_is_still_a_mutation_against_the_json_api():
    """Leave the mutations as mutations. What changed is the aftermath: the
    page rebuilt both panes from strings, and it re-requests the output
    fragment now."""
    js = _page_code()
    assert "api.post(" in js
    assert "/render?document_name=" in js
    assert "htmx.ajax('POST', '/ui/template-render/output'" in js


def test_the_markdown_step_is_the_one_thing_left_in_the_browser():
    """Deliberate, and the only client-side markup on the page. ION ships no
    HTML sanitiser, markdown.markdown passes raw HTML and javascript: hrefs
    through, and this content is a template filled in with values a user
    typed. safeMarkdown is marked plus DOMPurify, and the result is inserted
    as parsed nodes rather than through innerHTML."""
    js = _page_code()
    assert "safeMarkdown(" in js
    assert "DOMParser" in js
    assert "replaceChildren" in js
    assert "marked.parse" not in js, "safeMarkdown is the sanitising wrapper"


def test_one_definition_of_which_data_is_being_rendered():
    """Both fragment requests get it from the same function, so the output
    pane and the section cards can never be rendered from different data."""
    js = _page_code()
    assert js.count("function currentDataJson") == 1
    assert "htmx:configRequest" in js


def test_the_assembled_markdown_comes_from_the_rendered_textareas():
    """The page kept a third copy of each section in a `renderedSections`
    array and wrote to all three on every keystroke."""
    js = _page_code()
    assert "renderedSections" not in js
    assert "lastRenderedMarkdown" not in js
    assert "#section-cards textarea[data-idx]" in js
