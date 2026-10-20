"""The template view as a server-rendered fragment.

template_view.html built the tag chips, the variables table, the version
table, the version modal, the diff and the section cards with innerHTML.
escapeHtml() and formatDiff() were what kept a tag or a version message
from being markup. The cases below are the ones that string concatenation
got wrong, and the ones a later edit can quietly put back:

  * `c.level || 2` turned a recorded heading level of 0 into H2.
  * `c.ordered ? "Ordered" : "Unordered"` called a missing flag Unordered
    and the string "no" Ordered.
  * `|length` on the string "no" is 2, which was never a count.
  * `message || "-"` hid a message of 0 and an empty message the same way.
  * `is true` dropped a checkpoint that survived a round trip as 1, and
    truthiness badged the string "no".
  * a failed read rendered as "No variables detected" or "No version
    history available", which is the opposite claim.

Each assertion names that defect. A three-state check arranges True, False,
the integer 1 and the string "no": arranging only None passes for both
`is true` and truthiness, and so proves nothing.
"""
from __future__ import annotations

import enum
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.testclient import TestClient

from ion.core.exceptions import TemplateNotFoundError, VersionNotFoundError
from ion.services.section_types import SECTION_TYPES, assemble_jinja2

#: A parametrise value meaning "the key is absent", which is a different
#: input from the key holding None and used to be conflated with it.
_ABSENT = object()
from ion.web.templating import make_templates
from ion.web.ui.template_view import (
    PERMISSION,
    ROLLBACK_PERMISSION,
    _page_context,
    router,
)

FRAGMENT = "_fragments/template_view.html"
ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/template_view.html"
TEMPLATES = ROOT / "src/ion/web/templates"


def render(**ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(FRAGMENT).render(**ctx)


def template(**over: Any) -> dict:
    base = {
        "id": 7,
        "name": "Incident report",
        "content": "hello",
        "format": "markdown",
        "description": "A report",
        "document_type": "SOP",
        "current_version": 1,
        "tags": ["alpha"],
        "has_sections": False,
        "sections": None,
        "updated_at": "2026-10-12T14:51:00",
    }
    base.update(over)
    return base


def version(**over: Any) -> dict:
    base = {
        "version_number": 1,
        "message": "Initial version",
        "author": "ada",
        "is_checkpoint": False,
        "checkpoint_name": None,
        "created_at": "2026-10-12T14:51:00",
        "content": "body",
        "diff": None,
    }
    base.update(over)
    return base


def show(
    payload: dict | None,
    *,
    template_id: int = 7,
    template_state: str = "ok",
    variables: list | None = None,
    variables_state: str = "empty",
    versions: list | None = None,
    versions_state: str = "empty",
    can_rollback: bool = False,
) -> str:
    ctx = _page_context(
        template_id,
        template=payload,
        template_state=template_state,
        variables=variables,
        variables_state=variables_state,
        versions=versions,
        versions_state=versions_state,
        can_rollback=can_rollback,
    )
    return render(**ctx)


def sections_html(sections: object, **over: Any) -> str:
    payload = {"has_sections": True, "sections": sections}
    payload.update(over)
    return show(template(**payload))


def _request(path: str = "/ui/template-view/7"):
    from starlette.requests import Request

    return Request({
        "type": "http", "method": "GET", "path": path, "headers": [],
        "query_string": b"", "scheme": "http", "server": ("testserver", 80),
        "root_path": "",
    })


class _User:
    def __init__(self, *, rollback: bool = False):
        self._rollback = rollback
        self.id = 1
        self.username = "tester"

    def has_permission(self, name: str) -> bool:
        if name == PERMISSION:
            return True
        if name == ROLLBACK_PERMISSION:
            return self._rollback
        return False


class _Versions:
    """Stand-in for Services. The route calls services.version, which is
    what VersionService is on the real container, so the methods live one
    attribute down rather than on the container itself."""

    def __init__(self, rows=None, exc=None, one=None, one_exc=None):
        self.version = self
        self.rows = [] if rows is None else rows
        self.exc = exc
        self.one = one
        self.one_exc = one_exc

    def list_versions(self, template_id):
        if self.exc is not None:
            raise self.exc
        return self.rows

    def get_version(self, template_id, version_number):
        if self.one_exc is not None:
            raise self.one_exc
        return self.one


def _call(monkeypatch, fn_name: str, **kwargs):
    """The route itself, with the two payload functions stubbed.

    Rendering a state by passing it to the template proves the markup and
    says nothing about whether the route ever selects it. An except that
    rendered an empty table would be the page's defect and would leave
    every template-only assertion green.
    """
    from ion.web.ui import template_view as mod

    template_exc = kwargs.pop("template_exc", None)
    payload = kwargs.pop("payload", template())
    variables_exc = kwargs.pop("variables_exc", None)
    variables = kwargs.pop("variables", {"extracted": [], "defined": []})

    def read_template(services, template_id):
        if template_exc is not None:
            raise template_exc
        return payload

    def read_variables(services, template_id):
        if variables_exc is not None:
            raise variables_exc
        return variables

    monkeypatch.setattr(mod, "template_payload", read_template)
    monkeypatch.setattr(mod, "template_variables_payload", read_variables)
    services = _Versions(
        rows=kwargs.pop("rows", []),
        exc=kwargs.pop("versions_exc", None),
        one=kwargs.pop("one", None),
        one_exc=kwargs.pop("one_exc", None),
    )
    user = kwargs.pop("user", _User(rollback=True))
    fn = getattr(mod, fn_name)
    # `current_user`, not `user`: the read permission is declared on the
    # decorator and the User arrives from get_current_user, so calling the
    # function directly supplies only the object. What the decorator declares
    # is read off the live route by tests/unit/test_ui_fragment_registry.py,
    # which is where that assertion belongs.
    response = fn(
        request=_request(), current_user=user, services=services, **kwargs
    )
    assert response.status_code == 200
    return response.body.decode("utf-8")


def call_page(monkeypatch, **kwargs) -> str:
    kwargs.setdefault("template_id", 7)
    return _call(monkeypatch, "template_view_fragment", **kwargs)


def call_version(monkeypatch, **kwargs) -> str:
    kwargs.setdefault("template_id", 7)
    kwargs.setdefault("version_number", 1)
    return _call(monkeypatch, "template_view_version_fragment", **kwargs)


# ---------------------------------------------------------------------------
# Section cards. These are the page's renderSectionCards, which had no
# server equivalent, so the display rules live here and are easy to regress.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("level,expect", [
    (0, "Level: H0"),
    (None, "Level: H2"),
    ("", "Level: H2"),
])
def test_a_heading_level_of_zero_stays_zero(level, expect):
    """`c.level || 2` is the expression that turned a recorded 0 into H2.

    None and "" are the editor's default and must still read H2, or a test
    that only arranged 0 would also pass for a function that always returns
    the raw value and never applies the default. "Level: H2" contains the
    prefix "Level: H", so the empty-string case is checked by the element
    text rather than by that prefix being absent.
    """
    config: dict[str, object] = {"text": "Scope"}
    if level is not None:
        config["level"] = level
    html = sections_html([{"type": "heading", "config": config}])
    assert expect in html
    if level == 0:
        assert "Level: H2" not in html
    else:
        assert "Level: H0" not in html
        assert "Level: HNone" not in html
        # str("") concatenated after "Level: H" sits against the closing tag.
        # "Level: H2" does not, so this does not reject the default.
        assert not re.search(r"Level: H\s*</div>", html)


def test_a_missing_level_key_uses_the_editor_default():
    """The key being absent is a different input from the key holding None.
    Both used to take the same `|| 2` path."""
    html = sections_html([{"type": "heading", "config": {"text": "Scope"}}])
    assert "Level: H2" in html
    assert "Level: H0" not in html


@pytest.mark.parametrize("flag", [True, 1, "no", "false", False, 0, None, _ABSENT])
def test_the_ordered_label_says_what_the_document_will_contain(flag):
    """The card is a preview, so its word has to match the assembler.

    The expected value is computed from `assemble_jinja2`, the function that
    turns the stored section into document content, rather than written down
    here. A hardcoded table is what let the previous version of this test
    assert "Order not recorded" for the string "no", which is a list the
    assembler renders ORDERED: it reads the flag as
    `config.get("ordered", False)` and then `if ordered:`, so any truthy
    value including a non-empty string means ordered.

    Written this way the test fails if either side drifts, which is the
    property that matters: the defect is the two disagreeing, and neither one
    is independently wrong.
    """
    config: dict[str, object] = {"items": ["one"]}
    if flag is not _ABSENT:
        config["ordered"] = flag
    section = {"type": "list", "config": config}

    rendered = assemble_jinja2([section])
    assert rendered.strip() in ("1. one", "- one"), rendered
    word = "Ordered" if rendered.strip().startswith("1.") else "Unordered"

    html = sections_html([section])
    assert f"{word} - 1 items" in html
    other = "Unordered" if word == "Ordered" else "Ordered"
    assert f"{other} - " not in html
    # The label this helper used to emit for None, a missing key and "no".
    assert "Order not recorded" not in html


def test_a_string_is_not_a_count_of_items():
    """`|length` on the string "no" is 2. That 2 was never measured, and
    printing it is a count of items the section does not have."""
    html = sections_html([
        {"type": "list", "config": {"ordered": True, "items": "no"}},
    ])
    assert "item count unknown" in html
    assert "2 items" not in html


def test_an_empty_item_list_is_a_count_of_zero():
    """The control for the test above. A list that was read and is empty
    has a count of 0, which is not "unknown"."""
    html = sections_html([
        {"type": "list", "config": {"ordered": False, "items": []}},
    ])
    assert "Unordered - 0 items" in html
    assert "item count unknown" not in html


@pytest.mark.parametrize("stype,key,word", [
    ("list", "items", "items"),
    ("key_value", "pairs", "pairs"),
])
def test_an_items_key_holding_none_is_a_count_of_zero_not_unknown(stype, key, word):
    """A key holding None is a different input from the key being absent,
    and `_count` deliberately treats both as 0: the section was read, and it
    names nothing. "unknown" would claim we could not look.

    Known gap, recorded here because this is where the next person will see
    it. The assembler does `config.get(key, [])`, which returns None when
    the key is PRESENT and holds None, and then raises TypeError on
    `enumerate(None)`. So a section in this shape cannot be assembled at
    all and the card's "0" describes a document nobody can produce. The
    fault is the assembler's `get(key, [])` where it wants `get(key) or []`,
    in ion/services/section_types.py, which is not this page's file. This
    card matches what the assembler would say once that is fixed.
    """
    import pytest as _pytest
    with _pytest.raises(TypeError):
        assemble_jinja2([{"type": stype, "config": {key: None}}])

    html = sections_html([{"type": stype, "config": {key: None}}])
    assert f"0 {word}" in html
    assert f"{word.rstrip('s')} count unknown" not in html
    assert "count unknown" not in html


@pytest.mark.parametrize("stype,key,claim", [
    ("table", "columns", "columns unreadable"),
    ("metadata_block", "fields", "fields unreadable"),
    ("signature_block", "roles", "roles unreadable"),
])
def test_a_string_is_not_a_list_of_names(stype, key, claim):
    """`", ".join("ab")` is "a, b". Joining a string one character at a
    time reads as two names nobody stored."""
    html = sections_html([{"type": stype, "config": {key: "ab"}}])
    assert claim in html
    assert "a, b" not in html


def test_a_real_column_list_is_joined_and_an_empty_one_is_not_unreadable():
    """The control. A helper that always says "unreadable" passes the test
    above and is just as wrong."""
    joined = sections_html([{
        "type": "table",
        "config": {"columns": [{"name": "Host"}, {"name": "User"}]},
    }])
    assert "Host, User" in joined
    assert "columns unreadable" not in joined
    empty = sections_html([{"type": "table", "config": {"columns": []}}])
    assert "columns unreadable" not in empty
    assert "Host" not in empty


@pytest.mark.parametrize("flag", [True, 1])
def test_a_variable_flag_that_is_on_shows_the_badge_not_the_content(flag):
    """True, or the integer 1 a JSON round trip hands back. `is True` alone
    hides the badge for 1 and prints the content as the title instead."""
    html = sections_html([{
        "type": "text",
        "config": {
            "variable": flag,
            "variable_name": "widget",
            "content": "SECRETCONTENT",
        },
    }])
    assert "sv-var-badge" in html
    assert "widget" in html
    assert "SECRETCONTENT" not in html


@pytest.mark.parametrize("flag", [False, 0, None, _ABSENT])
def test_a_variable_flag_that_is_not_on_shows_the_content(flag):
    """A text section with the flag off renders its stored content.

    The string "no" is deliberately not in this list and is covered by the
    test below instead. It is truthy, so the assembler substitutes the
    variable for it, and a card claiming the static content would be
    describing a document nobody will get.
    """
    config: dict[str, object] = {
        "variable_name": "widget", "content": "SECRETCONTENT",
    }
    if flag is not _ABSENT:
        config["variable"] = flag
    section = {"type": "text", "config": config}

    assert assemble_jinja2([section]).strip() == "SECRETCONTENT"
    html = sections_html([section])
    assert "sv-var-badge" not in html
    assert "SECRETCONTENT" in html
    assert "widget" not in html


@pytest.mark.parametrize("flag", ["no", "false", 1, True])
def test_a_truthy_variable_flag_shows_the_badge_because_the_document_will(flag):
    """Any truthy flag means the document carries the variable, not the text.

    The assembler is `config.get("variable", False)` then `if is_variable
    and var_name`, so `variable: "no"` with a name emits `{{ widget }}` and
    the stored content never appears. This card used to call that flag off,
    on the reasoning that nobody had turned it on, and so showed
    SECRETCONTENT as the section's title for a section that renders as a
    variable. The expected result is read off the assembler so the two
    cannot drift.
    """
    section = {
        "type": "text",
        "config": {
            "variable": flag, "variable_name": "widget",
            "content": "SECRETCONTENT",
        },
    }
    assert assemble_jinja2([section]).strip() == "{{ widget }}"
    html = sections_html([section])
    assert "sv-var-badge" in html
    assert "widget" in html
    assert "SECRETCONTENT" not in html


def test_a_variable_name_is_escaped():
    """escapeHtml() used to do this. Jinja does it now, and a badge that
    interpolates the name raw is a stored XSS on a template someone can edit."""
    html = sections_html([{
        "type": "text",
        "config": {"variable": True, "variable_name": "<script>"},
    }])
    assert "&lt;script&gt;" in html
    assert "<script>" not in html


def test_a_chain_variable_of_zero_is_not_replaced_by_the_default():
    """`value || "chain_of_custody"` turns a stored 0 into the default.
    0 is a name that was stored. Only a missing one takes the default."""
    zero = sections_html([{
        "type": "evidence_block",
        "config": {"source": "disk", "chain_of_custody_var": 0},
    }])
    assert "&#123;&#123; 0 &#125;&#125;" in zero
    assert "chain_of_custody" not in zero
    missing = sections_html([{
        "type": "evidence_block",
        "config": {"source": "disk"},
    }])
    assert "chain_of_custody" in missing


def test_a_caption_is_text_and_not_a_link():
    """There is no stored URL on this page. A caption of `javascript:...`
    used to be one `href` away from being one, and the plan tool flags every
    page that builds a URL. This one must not."""
    html = sections_html([{
        "type": "image_placeholder",
        "config": {
            "caption": "javascript:alert(1)",
            "variable_name": "shot",
        },
    }])
    assert "javascript:alert(1)" in html
    assert "href=" not in html


def test_a_known_section_type_uses_the_library_label_not_the_script_copy():
    """The script's sectionMeta said "Key-Value". SECTION_TYPES, which is
    what GET /api/templates/section-types returns, says "Key-Value Pairs".
    A hand-copied shorter dict fails this because the expected text is the
    library's own."""
    label = SECTION_TYPES["key_value"]["label"]
    icon = SECTION_TYPES["key_value"]["icon"]
    html = sections_html([{"type": "key_value", "config": {"pairs": []}}])
    assert f'class="sv-card-type">{label}</span>' in html
    assert f'class="sv-card-icon">{icon}</div>' in html
    assert label != "Key-Value"


def test_an_unknown_section_type_names_itself_and_a_non_object_says_so():
    """Dropping a section that is not an object lowers the count, which
    reads as a shorter template. An unknown type is not the word None."""
    html = sections_html([
        {"type": "heading", "config": {"text": "Scope", "level": 2}},
        {"type": "made_up", "config": {}},
        "no",
    ])
    assert 'class="sv-card-type">made_up</span>' in html
    assert 'class="sv-card-icon">?</div>' in html
    assert "Unreadable section" in html
    assert "Scope" in html
    assert 'id="section-count-badge">3</span>' in html
    assert 'sv-card-type">None' not in html


# ---------------------------------------------------------------------------
# Which body. has_sections is three states, and the string "no" is the one
# truthiness gets wrong.
# ---------------------------------------------------------------------------


def test_has_sections_true_with_no_sections_is_a_count_of_zero():
    """A template that has sections and currently none of them is a count
    of 0. That is not the raw body and not "we could not tell"."""
    html = sections_html([])
    assert 'id="section-count-badge">0</span>' in html
    assert "not a yes or a no" not in html
    assert 'id="raw-content-view"' not in html


@pytest.mark.parametrize("flag", ["no", 1])
def test_has_sections_that_is_not_a_boolean_shows_neither_body(flag):
    """Truthiness treats "no" as on and would render the Scope card. `is
    true` alone treats the integer 1 as off, which is the other wrong
    answer: 1 is not a yes either, because this flag is a boolean and not
    the SQLite 0/1 of a checkpoint. Neither body is honest."""
    html = sections_html(
        [{"type": "heading", "config": {"text": "Scope", "level": 2}}],
        has_sections=flag,
    )
    assert "not a yes or a no" in html
    assert "Scope" not in html
    assert "section-count-badge" not in html
    assert "Level:" not in html
    assert "(empty)" not in html


def test_has_sections_true_with_a_non_list_is_the_same_unreadable_state():
    """True says the template is sectioned. A sections value that is not a
    list is not zero sections, and `|length` on the string "no" is 2."""
    html = sections_html("no", has_sections=True)
    assert "not a yes or a no" in html
    assert "section-count-badge" not in html
    # `|length` on the string "no" is 2. A badge is the claim that was measured.
    assert ">2</span>" not in html


def test_has_sections_false_shows_the_raw_body_and_zero_is_not_empty():
    """False is the legacy body. content 0 is a body; "" and None are the
    absence of one, which the page's `content || "(empty)"` collapsed, and
    which must not also swallow a body whose text is "0". A sections list
    sitting next to False is not what gets rendered."""
    zero = show(template(
        has_sections=False, content=0,
        sections=[{"type": "heading", "config": {"text": "Scope", "level": 2}}],
    ))
    assert 'id="template-content"' in zero
    assert ">0</pre>" in zero
    assert "(empty)" not in zero
    assert "Scope" not in zero

    blank = show(template(has_sections=False, content=""))
    assert "(empty)" in blank
    assert ">0</pre>" not in blank

    missing = show(template(has_sections=False, content=None))
    assert "(empty)" in missing


@pytest.mark.parametrize("description,text", [
    (0, "0"),
    (None, "No description"),
    ("", "No description"),
    ("A report", "A report"),
])
def test_a_description_of_zero_is_a_description(description, text):
    """`description || "No description"` hides a description of 0 and an
    absent one with the same sentence."""
    html = show(template(description=description, has_sections=False, content="x"))
    found = re.search(
        r'id="template-description"[^>]*>(.*?)</p>', html, re.S,
    )
    assert found is not None
    assert found.group(1) == text


# ---------------------------------------------------------------------------
# The meta line: version 0, tags, enums, the clock.
# ---------------------------------------------------------------------------


def test_version_zero_is_a_version_and_a_missing_one_is_not_zero():
    """`current_version || "?"` and a truthiness check both render v0 as
    unknown, and rendering a missing version as v0 invents a version nobody
    reported."""
    zero = show(template(current_version=0))
    assert 'id="template-version">v0</span>' in zero
    assert "version unknown" not in zero

    missing = show(template(current_version=None))
    assert 'id="template-version">version unknown</span>' in missing
    assert "v0" not in missing
    assert "vNone" not in missing


def test_tags_are_escaped_and_a_non_list_is_not_no_tags():
    """A string rendered as a list is one chip per character. None is not
    "no tags": an empty list is no tags."""
    hostile = show(template(tags=["<script>alert(1)</script>"]))
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in hostile
    assert "<script>" not in hostile

    unread = show(template(tags="ab"))
    assert "not the same as no tags" in unread
    assert "No tags" not in unread
    assert 'class="tag">a</span>' not in unread

    none = show(template(tags=[]))
    assert "No tags" in none
    assert "not the same as no tags" not in none


class _Fmt(enum.Enum):
    """Not a str mixin, so str() is the repr and not the value."""

    MARKDOWN = "markdown"


class _Doc(enum.Enum):
    PROCEDURE = "SOP"


class _Kind(enum.Enum):
    TEXT = "string"


def test_format_and_document_type_render_the_value_not_the_enum_repr():
    """Template.format and document_type are String columns today. plain()
    wraps them because a column that later becomes an enum renders as
    Format.MARKDOWN under str(), and only the text is wrong. A type that
    is not a CSS token is still shown, and is not interpolated into the
    class."""
    html = show(template(format=_Fmt.MARKDOWN, document_type=_Doc.PROCEDURE))
    assert 'id="template-format">markdown</span>' in html
    assert "_Fmt" not in html
    assert "MARKDOWN" not in html
    assert 'data-doctype="SOP"' in html
    assert "_Doc" not in html
    assert "PROCEDURE" not in html

    hostile = show(template(document_type='"><script>'))
    # The type is a free-form String, so it used to be screened before being
    # concatenated into a class. It is an attribute value now: the screen
    # still blanks it, the chip keeps its own class, and the label is
    # escaped. An empty data-doctype matches no row and reads as muted.
    assert 'class="v-chip"' in hostile
    assert 'data-doctype=""' in hostile
    assert "doc-type-" not in hostile
    assert "<script>" not in hostile
    assert "&lt;script&gt;" in hostile


def test_a_timestamp_is_a_time_element_and_a_missing_one_is_not_the_epoch():
    """The page called formatDate(), which is the viewer's clock. The
    fragment emits the ts macro. A missing updated_at is the fallback, never
    1970, and a datetime is not pre-formatted in Python."""
    stamped = show(template(updated_at=datetime(2026, 10, 12, 14, 51)))
    assert "<time " in stamped
    assert "2026-10-12 14:51" in stamped
    assert "1970" not in stamped

    blank = show(template(updated_at=None))
    assert "<time " not in blank
    assert "1970" not in blank
    assert 'id="template-updated">Updated: <span class="opacity-60">-</span>' in blank


# ---------------------------------------------------------------------------
# Variables. The route selects the state; the template must not collapse it.
# ---------------------------------------------------------------------------


def test_the_route_renders_the_payload_it_was_given(monkeypatch):
    """Positive control, and the proof the route calls template_payload
    rather than a second query. A route that never called the stub would
    not contain this name."""
    html = call_page(monkeypatch, payload=template(name="FROM-PAYLOAD"))
    assert "FROM-PAYLOAD" in html
    assert "could not be read" not in html


def test_no_variables_and_an_unreadable_variable_list_are_different(monkeypatch):
    """extracted="no" is not an empty list. `|length` is not the question,
    and "No variables detected" is the wrong answer to it."""
    empty = call_page(
        monkeypatch, variables={"extracted": [], "defined": []},
    )
    assert "No variables detected" in empty
    assert "not a list" not in empty

    unread = call_page(monkeypatch, variables={"extracted": "no", "defined": []})
    assert "not a list" in unread
    assert "No variables detected" not in unread
    assert "could not be read" not in unread


def test_a_failed_variable_read_is_not_an_empty_list(monkeypatch):
    """The template read succeeded. The variables read did not. The name
    still shows, and the variables slot says the read failed rather than
    that the template has no variables."""
    html = call_page(
        monkeypatch,
        payload=template(name="Incident report"),
        variables_exc=RuntimeError("variables unreachable"),
    )
    assert "Incident report" in html
    assert "Variables could not be read" in html
    assert "No variables detected" not in html


@pytest.mark.parametrize("defined", [1, "no"])
def test_a_defined_flag_that_is_not_a_boolean_says_unknown(defined):
    """`if row.defined` treats the string "no" as defined and the integer 1
    as defined. `is true` / `is false` / else keeps both as unknown. A test
    that only arranges None passes for the truthiness bug, because None is
    falsy and lands in the else either way."""
    html = show(
        template(),
        variables=[{"name": "widget", "defined": defined, "var_type": "string"}],
        variables_state="ok",
    )
    assert "Unknown" in html
    assert "Defined" not in html
    assert "Not defined" not in html


def test_defined_true_and_false_are_the_two_answers_unknown_is_not(monkeypatch):
    """The control for the test above. A template that always says Unknown
    passes that one and is wrong about every real row. var_type 0 is a type;
    None is a defined variable that named none, which is a dash."""
    yes = call_page(monkeypatch, variables={
        "extracted": ["widget"],
        "defined": [{"name": "widget", "var_type": 0}],
    })
    assert re.search(
        r"<td>0</td>\s*<td><span class=\"badge badge-success\">Defined</span>",
        yes,
    )
    assert "_Kind" not in yes

    typed = call_page(monkeypatch, variables={
        "extracted": ["widget"],
        "defined": [{"name": "widget", "var_type": _Kind.TEXT}],
    })
    assert ">string</td>" in typed
    assert "_Kind" not in typed
    assert "TEXT" not in typed

    bare = call_page(monkeypatch, variables={
        "extracted": ["widget"],
        "defined": [{"name": "widget", "var_type": None}],
    })
    assert re.search(
        r"<td>-</td>\s*<td><span class=\"badge badge-success\">Defined</span>",
        bare,
    )
    assert "<td>0</td>" not in bare

    no = call_page(monkeypatch, variables={
        "extracted": ["widget"], "defined": [],
    })
    assert "Not defined" in no
    assert "Unknown" not in no
    assert ">Defined<" not in no

    # defined not being a list is not "every variable is undefined".
    unread = call_page(monkeypatch, variables={
        "extracted": ["widget"], "defined": "no",
    })
    assert "Unknown" in unread
    assert "Not defined" not in unread


def test_a_failed_template_read_does_not_invent_an_empty_template(monkeypatch):
    """A failed read renders a fragment that says so. It does not print no
    tags, no description, an empty body or version 0, all of which are
    claims that something was read and found blank."""
    html = call_page(
        monkeypatch, template_exc=RuntimeError("database gone"),
    )
    assert "This template could not be read" in html
    assert "The template body could not be read" in html
    assert "No tags" not in html
    assert "No description" not in html
    assert "(empty)" not in html
    assert "section-count-badge" not in html
    assert 'id="template-version"' not in html
    assert "v0" not in html
    for slot in (
        'id="template-name"', 'id="template-body"',
        'id="template-variables"', 'id="versions-list"',
    ):
        assert slot in html, slot


def test_a_missing_template_is_not_a_failed_read(monkeypatch):
    """TemplateNotFoundError is what the JSON route turns into 404. The
    fragment says the template is not there, which is a different next
    step from trying the read again."""
    missing = TemplateNotFoundError(7)
    html = call_page(
        monkeypatch,
        template_exc=missing,
        variables_exc=missing,
        versions_exc=missing,
    )
    assert "There is no template 7" in html
    assert "could not be read" not in html
    assert "No variables detected" not in html
    assert "No version history available" not in html
    assert "unknown rather than absent" in html
    assert "unknown rather than empty" in html


def test_one_read_failing_does_not_blank_the_others(monkeypatch):
    """The template read failed. The variables and the history did not.
    Rollback is withheld anyway: which row is current is then unknown, and
    offering rollback on that basis can roll the live version back to itself."""
    html = call_page(
        monkeypatch,
        template_exc=RuntimeError("database gone"),
        variables={
            "extracted": ["widget"],
            "defined": [{"name": "widget", "var_type": "string"}],
        },
        rows=[version(version_number=3, message="kept")],
        user=_User(rollback=True),
    )
    assert "could not be read" in html
    assert "widget" in html
    assert ">Defined<" in html
    assert "kept" in html
    assert "current unknown" in html
    assert "Rollback" not in html
    assert ">Current<" not in html


def test_a_row_known_not_to_be_current_is_badged_neither_way():
    """The middle branch of a three-state is empty, which is the shape the
    contract says to mutate by deleting.

    `is_current` is True, False or None. True gets "Current", None gets
    "current unknown", and False gets NOTHING, because a row that is simply
    an older version does not need labelling. Deleting the empty
    `{% elif row.is_current is false %}` arm leaves the Jinja balanced and
    sends every older version into the else, so each one claims its own
    currency is unknown while the page knows perfectly well that it is not
    current. That survived the first mutation pass: no test arranged a
    known-false row and asserted the absence of BOTH badges.

    All three states are arranged here, so the test cannot pass by only
    covering the easy two.
    """
    rows = [version(version_number=n, message=f"m{n}") for n in (3, 2, 1)]
    known = show(template(current_version=3), versions=rows,
                 versions_state="ok")
    assert known.count(">Current<") == 1
    assert "current unknown" not in known
    # Positive control: all three rows really did render, so the absence of
    # the badge is not the absence of the table.
    for n in (3, 2, 1):
        assert f"m{n}" in known

    unknown = show(template(current_version=None), versions=rows,
                   versions_state="ok")
    assert unknown.count("current unknown") == 3
    assert ">Current<" not in unknown


def test_a_failed_history_read_leaves_the_template_standing(monkeypatch):
    html = call_page(
        monkeypatch,
        payload=template(name="Incident report"),
        versions_exc=RuntimeError("history unreachable"),
    )
    assert "Incident report" in html
    assert "Version history could not be read" in html
    assert "No version history available" not in html
    assert "This template could not be read" not in html


def test_an_empty_history_says_so(monkeypatch):
    """The control for the failure test. A route that always says the read
    failed passes that one."""
    html = call_page(monkeypatch, rows=[])
    assert "No version history available" in html
    assert "could not be read" not in html


# ---------------------------------------------------------------------------
# Version rows. 0 is a version, "" is a message, 1 is a checkpoint.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("message,cell", [
    (0, "<td class=\"version-message\"><span>0</span></td>"),
    ("", "<td class=\"version-message\"><span></span></td>"),
    (None,
     "<td class=\"version-message\"><span class=\"opacity-60\">No message</span></td>"),
])
def test_a_message_of_zero_is_a_message_and_a_blank_one_is_not_a_dash(message, cell):
    """`v.message || "-"` renders 0, "" and None as the same dash. 0 was
    stored. "" was stored and is empty. None was not stored.

    The cell is versions_meta.html's `message` macro, so the three outcomes
    and their wording are versions.py's, not a second set. The whole cell is
    asserted rather than a substring: "No message" contains "message", and
    the column header is the word "Message", so a substring check here would
    pass against the header on a row that rendered nothing at all.
    """
    html = show(
        template(),
        versions=[version(message=message, author="ada")],
        versions_state="ok",
    )
    assert cell in html


@pytest.mark.parametrize("author,cell", [
    (0, "<td class=\"version-author\">0</td>"),
    ("", "<td class=\"version-author\"></td>"),
    (None, "<td class=\"version-author\">-</td>"),
])
def test_an_author_of_zero_is_an_author(author, cell):
    html = show(
        template(),
        versions=[version(author=author)],
        versions_state="ok",
    )
    assert cell in html


@pytest.mark.parametrize("flag,name,shows", [
    (1, "nightly", "nightly"),
    (True, "<script>", "&lt;script&gt;"),
    (True, None, "Checkpoint"),
])
def test_a_checkpoint_of_one_shows_and_a_nameless_one_still_says_so(flag, name, shows):
    """`is true` drops the integer 1, which a round trip through JSON or a
    raw SQLite row hands back for a Boolean. A checkpoint with no name still
    says it is one, rather than badging the word None, which is what
    `escapeHtml(v.checkpoint_name)` under a bare `if (v.is_checkpoint)` did.

    The badge is versions_meta.html's `checkpoint_badge` macro, so the class
    is `checkpoint-badge` and the rule has one definition across this page
    and versions.py.
    """
    html = show(
        template(),
        versions=[version(is_checkpoint=flag, checkpoint_name=name)],
        versions_state="ok",
    )
    assert "checkpoint-badge" in html
    assert shows in html
    assert "<script>" not in html
    assert ">None<" not in html


@pytest.mark.parametrize("flag", [0, False])
def test_a_checkpoint_flag_that_is_not_on_draws_no_badge(flag):
    """0 and False are the two values that mean "not a checkpoint".

    The string "no" is deliberately not among them. TemplateVersion.
    is_checkpoint is a non-nullable Boolean column, so it has two states and
    cannot deliver a string, and versions_meta.checkpoint_badge tests it with
    truthiness for exactly that reason: `is true` would drop the integer 1 a
    round trip hands back. Arranging "no" here would assert a stricter rule
    than the shared macro's, which is how this page would end up with a
    second definition of the badge.
    """
    html = show(
        template(),
        versions=[version(is_checkpoint=flag, checkpoint_name="nightly",
                          message="a message that proves the row rendered")],
        versions_state="ok",
    )
    # Positive control first. Both assertions below are negative, so without
    # this the test passes for a render that produced nothing at all, which
    # is the shape that has shipped twice today.
    assert "a message that proves the row rendered" in html
    assert "checkpoint-badge" not in html
    assert "nightly" not in html


def test_version_zero_that_is_current_offers_no_rollback_and_can_be_viewed():
    """`if version_number` treats 0 as absent, so the current row loses its
    badge and the View button, and a rollback of the live version to itself
    becomes the thing on offer. The URL is one value: a concatenation that
    inserts `&amp;` fails this."""
    html = show(
        template(current_version=0),
        versions=[version(version_number=0, message="genesis")],
        versions_state="ok",
        can_rollback=True,
    )
    assert 'class="current-version"' in html
    assert ">Current<" in html
    assert "Rollback" not in html
    assert 'hx-get="/ui/template-view/7/versions/0"' in html
    assert "v0" in html


def test_version_zero_that_is_not_current_can_be_rolled_back():
    """The button's argument is a JSON array. `[0]` parses as the number 0.
    A truthiness check in the handler, or a button that omits 0, refuses
    the only version some templates start at."""
    html = show(
        template(current_version=1),
        versions=[version(version_number=0)],
        versions_state="ok",
        can_rollback=True,
    )
    assert "Rollback" in html
    assert ">Current<" not in html
    assert 'class="current-version"' not in html
    found = re.search(r"""data-args='(\[[^']*\])'""", html)
    assert found is not None
    assert json.loads(found.group(1)) == [0]


def test_version_zero_with_no_known_current_offers_no_rollback():
    """current is None when the template read did not say. That is not
    "this row is not current". Offering rollback here is a guess."""
    html = show(
        template(current_version=None),
        versions=[version(version_number=0)],
        versions_state="ok",
        can_rollback=True,
    )
    assert "current unknown" in html
    assert "Rollback" not in html
    assert ">Current<" not in html
    assert 'hx-get="/ui/template-view/7/versions/0"' in html


def test_a_viewer_who_cannot_roll_back_is_not_offered_the_button():
    """The endpoint still refuses. The button is withheld so the viewer
    does not have to click to learn that. The control is the same row with
    the permission, which does offer it."""
    denied = show(
        template(current_version=1),
        versions=[version(version_number=2)],
        versions_state="ok",
        can_rollback=False,
    )
    assert "Rollback" not in denied
    assert 'hx-get="/ui/template-view/7/versions/2"' in denied

    allowed = show(
        template(current_version=1),
        versions=[version(version_number=2)],
        versions_state="ok",
        can_rollback=True,
    )
    assert ">Rollback</button>" in allowed


def test_a_version_timestamp_uses_the_macro_and_a_missing_one_is_not_1970():
    stamped = show(
        template(updated_at=None),
        versions=[version(created_at=datetime(2026, 10, 12, 14, 51))],
        versions_state="ok",
    )
    assert "<time " in stamped
    assert "2026-10-12 14:51" in stamped

    blank = show(
        template(updated_at=None),
        versions=[version(created_at=None)],
        versions_state="ok",
    )
    assert "<time " not in blank
    assert "1970" not in blank


# ---------------------------------------------------------------------------
# The version modal. Close is in every state because the modal is the swap.
# ---------------------------------------------------------------------------


def test_the_diff_marks_adds_and_deletes_and_not_the_file_headers(monkeypatch):
    """formatDiff tagged a line as an add when it started with "+" but not
    "+++", and a delete when it started with "-" but not "---". The file
    headers are neither. The line text is escaped."""
    html = call_version(
        monkeypatch,
        one=version(diff="+added\n+++ b\n--- a\n-gone\n <script>"),
        payload=template(current_version=1),
        version_number=2,
    )
    adds = re.findall(r'<span class="diff-add">(.*?)</span>', html)
    deletes = re.findall(r'<span class="diff-del">(.*?)</span>', html)
    assert adds == ["+added"]
    assert deletes == ["-gone"]
    assert "+++ b" in html
    assert "--- a" in html
    assert "&lt;script&gt;" in html
    assert "<script>" not in html


def test_a_missing_diff_an_empty_diff_and_an_unreadable_diff_differ(monkeypatch):
    """None means nobody stored a diff. "" means a diff was stored and has
    no lines: `"".split("\\n")` is one blank line, which would render as a
    diff that has a line in it. A number is not a diff, and saying so with
    the empty-diff sentence is the same lie as printing 0."""
    none = call_version(monkeypatch, one=version(diff=None))
    assert "No diff available" in none
    assert "stored diff is empty" not in none

    empty = call_version(monkeypatch, one=version(diff=""))
    assert "stored diff is empty" in empty
    assert "No diff available" not in empty

    unread = call_version(monkeypatch, one=version(diff=123))
    assert "not the same as a diff that is empty" in unread
    assert "stored diff is empty" not in unread
    assert "No diff available" not in unread


def test_a_failed_version_read_and_a_missing_version_both_keep_close(monkeypatch):
    """200, because htmx does not swap a 500 and the modal would stay on
    its spinner. Close is in both: the modal is the swap, so an error that
    returned only the alert leaves it open with no way out. The two
    sentences are different claims."""
    failed = call_version(
        monkeypatch, one_exc=RuntimeError("version store unreachable"),
        version_number=4,
    )
    assert "could not be read" in failed
    assert "does not exist" not in failed
    assert 'class="modal show"' in failed
    assert 'data-remove-closest=".modal"' in failed
    assert ">Close<" in failed

    missing = call_version(
        monkeypatch, one_exc=VersionNotFoundError(7, 99), version_number=99,
    )
    assert "Version 99" in missing
    assert "does not exist" in missing
    assert "could not be read" not in missing
    assert 'class="modal show"' in missing
    assert 'data-remove-closest=".modal"' in missing
    assert ">Close<" in missing


def test_version_content_of_zero_is_not_empty_and_rollback_needs_a_current(monkeypatch):
    """`content || "(empty)"` hides a stored 0. The template read failing
    does not hide the version; it withholds rollback, because the button
    depends on knowing which version is live."""
    zero = call_version(
        monkeypatch,
        one=version(version_number=2, content=0),
        payload=template(current_version=1),
        version_number=2,
        user=_User(rollback=True),
    )
    assert 'id="version-content"' in zero
    assert ">0</pre>" in zero
    assert "(empty)" not in zero
    assert 'id="rollback-btn"' in zero
    assert ">Close<" in zero

    blind = call_version(
        monkeypatch,
        template_exc=RuntimeError("database gone"),
        one=version(version_number=2, content="kept"),
        version_number=2,
        user=_User(rollback=True),
    )
    assert "kept" in blind
    assert 'id="rollback-btn"' not in blind
    assert ">Close<" in blind


def test_checkpoint_one_in_the_modal_uses_the_same_rule(monkeypatch):
    """The modal's meta line and the table row now call the same macro.

    They used to be two copies of the rule, and `is true` alone would have
    dropped the integer 1 on this copy only, which a test of the table could
    not see. Both call versions_meta.checkpoint_badge, so this asserts the
    modal actually routes through it rather than keeping a local branch:
    the macro's own class name is the evidence, since a hand-written badge
    here would have carried this page's `badge badge-checkpoint`.
    """
    html = call_version(
        monkeypatch,
        one=version(is_checkpoint=1, checkpoint_name=None),
    )
    assert 'class="checkpoint-badge"' in html
    assert ">Checkpoint<" in html

    off = call_version(
        monkeypatch,
        one=version(is_checkpoint=False, checkpoint_name="nightly"),
    )
    assert "checkpoint-badge" not in off
    assert "nightly" not in off


# ---------------------------------------------------------------------------
# Gates. Read off the live routes. This page is not licence gated.
# ---------------------------------------------------------------------------


def _permission_of(route) -> str | None:
    stack, found = list(route.dependant.dependencies), None
    while stack:
        dep = stack.pop()
        fn = dep.call
        qual = getattr(fn, "__qualname__", "")
        if qual.startswith("require_permission."):
            cells = dict(zip(
                fn.__code__.co_freevars,
                (c.cell_contents for c in (fn.__closure__ or ())),
            ))
            found = cells.get("permission_name")
        stack.extend(dep.dependencies)
    return found


def _names(route) -> list[str]:
    stack, found = list(route.dependant.dependencies), []
    while stack:
        dep = stack.pop()
        found.append(getattr(dep.call, "__qualname__", ""))
        stack.extend(dep.dependencies)
    return found


def _api_route(path: str, method: str):
    from ion.web.api import router as api_router

    for route in api_router.routes:
        if getattr(route, "path", None) == path and method in route.methods:
            return route
    raise AssertionError(f"no {method} {path}")


_GETS = (
    "/templates/{template_id}",
    "/templates/{template_id}/variables",
    "/templates/{template_id}/versions",
    "/templates/{template_id}/versions/{version_number}",
)


def test_the_fragment_permission_is_the_json_gets_permission():
    """Read off the live routes rather than restated, so the fragment cannot
    stay on template:read while the API moves, and cannot be a softer way
    in. require_page_permission redirects to /login, which htmx would swap
    into the page."""
    for path in _GETS:
        route = _api_route(path, "GET")
        assert _permission_of(route) == PERMISSION, path
        assert "require_de_module" not in _names(route), path
    assert PERMISSION == "template:read"
    assert len(router.routes) == 2
    for route in router.routes:
        assert _permission_of(route) == PERMISSION
        names = _names(route)
        assert not any("require_de_module" in n for n in names)
        assert not any("require_page_permission" in n for n in names)
        assert route.response_class is HTMLResponse


def test_rollback_permission_is_the_live_post_and_not_the_read():
    """The button is withheld without this. The constant is checked against
    the POST route's own dependency, not against a second copy of the string
    alone: a test that only spells template:update passes while the route
    moves and the button stays behind the old permission."""
    post = _api_route("/templates/{template_id}/rollback/{to_version}", "POST")
    assert _permission_of(post) == ROLLBACK_PERMISSION
    assert ROLLBACK_PERMISSION == "template:update"
    assert ROLLBACK_PERMISSION != PERMISSION


def test_this_page_does_not_carry_the_detection_engineering_gate():
    """fragment_plan's live gates are template:read on the four GETs, and
    none of them is mounted behind require_de_module. Adding that gate
    would answer 404 for a template on a deployment that is licensed to
    have templates, while the page and the JSON API still served them.
    de_quirks carries the gate because its JSON route does. This one must
    not copy it.

    The positive control matters more than usual here: the only assertion
    is a negative one over a derived list, so if `_names` ever returned
    nothing this would pass while proving that the routes have no
    dependencies at all, which is the opposite of what anyone wants.
    """
    assert len(router.routes) == 2
    for route in router.routes:
        names = _names(route)
        assert any("require_permission" in n for n in names), (
            f"{route.path} has no permission dependency, so the absence of "
            f"require_de_module below proves nothing"
        )
        assert "require_de_module" not in _names(route)


def test_an_unparseable_id_is_a_validation_error_not_a_failed_read(session):
    """"We could not look" is reserved for a read that failed. A path
    segment that is not an integer is the caller's mistake."""
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    app = FastAPI()
    app.include_router(router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: _User(rollback=True)
    app.dependency_overrides[get_db_session] = lambda: session
    with TestClient(app) as client:
        page = client.get("/ui/template-view/nope")
        version = client.get("/ui/template-view/7/versions/nope")
    assert page.status_code == 422
    assert version.status_code == 422
    assert "could not be read" not in page.text
    assert "could not be read" not in version.text


# ---------------------------------------------------------------------------
# The page shell. Attributes are read off the element, not the file: a
# comment above #template-meta quotes hx-trigger="load", and a whole-file
# search passes from that sentence after the attribute is deleted.
# ---------------------------------------------------------------------------


def _page() -> str:
    return PAGE.read_text(encoding="utf-8")


def _strip(src: str) -> str:
    src = re.sub(r"\{#.*?#\}", "", src, flags=re.S)
    src = re.sub(r"<!--.*?-->", "", src, flags=re.S)
    return src


def _script(src: str) -> str:
    return "\n".join(
        re.findall(r"<script(?![^>]*src=)[^>]*>(.*?)</script>", src, re.S)
    )


def _meta_tag() -> str:
    found = re.search(r'<div id="template-meta"[^>]*>', _page(), re.S)
    assert found is not None, "no #template-meta element"
    return found.group(0)


def test_the_page_builds_no_markup_in_javascript():
    """Counted the way tools/ui_redesign_status.py counts it: the inline
    script body, comments included, because that tool does not strip them.
    hx-swap="innerHTML" is an attribute and is not in the script."""
    js = _script(_page())
    assert js.strip(), "no inline script, so this proves nothing"
    assert not re.findall(
        r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=", js,
    )
    assert "{{" not in js
    assert "{%" not in js


def test_the_meta_element_requests_the_fragment_and_names_no_event_filter():
    tag = _meta_tag()
    assert 'hx-get="/ui/template-view/{{ template_id }}"' in tag
    assert "load" in tag
    assert "click from:#tv-refresh" in tag
    assert "template-view:changed from:body" in tag
    assert 'hx-swap="innerHTML"' in tag
    assert "[" not in tag


def test_refresh_and_the_tabs_sit_outside_the_swap_target():
    """A control inside the fragment is removed by any render that omits it,
    so a failed read could take away the button that retries. The trigger
    attribute names #tv-refresh from inside the target; the button itself
    is before the target.

    Stripped first. This page carries a comment above #template-meta and
    another above #content-view, and an ordering assertion over raw source
    can be satisfied by a sentence rather than by an element, which is the
    trap the section header above describes.
    """
    src = _strip(_page())
    assert src.index('id="tv-refresh"') < src.index('id="template-meta"')
    assert src.index('href="/templates/{{ template_id }}/render"') < src.index(
        'id="template-meta"'
    )
    assert src.index('href="/templates/{{ template_id }}/edit"') < src.index(
        'id="template-meta"'
    )
    assert src.index('role="tablist"') > src.index('id="template-meta"')
    assert 'id="tv-page"' in src
    assert 'data-template-id="{{ template_id }}"' in src
    # The id is read off the element. Interpolating it into the script is
    # what makes node --check fail, and what a comment-blind search misses.
    assert "getAttribute('data-template-id')" in _script(src)
    assert "{{" not in _script(src)


def test_the_string_builders_are_gone_and_nothing_compiles_a_string():
    """Every assertion here is a negative, so each input gets a control.

    Without them a broken `_script` regex or a mistyped path would hand
    this test three empty strings and it would report success. Comments are
    stripped first, because the page quotes `escapeHtml` and `formatDiff`
    by name in the sentence explaining their removal, and the fragment's
    header names `innerHTML`.
    """
    src = _strip(_page())
    frag = _strip((TEMPLATES / FRAGMENT).read_text(encoding="utf-8"))
    js = re.sub(r"//[^\n]*", "", _script(src))
    assert "switchTab" in js, "no script body, so the loop below proves nothing"
    assert "version-modal" in frag, "fragment not read"
    assert "template-meta" in src, "page not read"

    for gone in ("renderSectionCards", "formatDiff", "escapeHtml"):
        assert gone not in js, gone
    for body in (src, frag):
        assert "hx-on" not in body
        assert "hx-vals" not in body
        assert "hx-headers" not in body
        assert "[key==" not in body
        assert "js:" not in body
        # No event filter in any trigger: htmx hands one to Function() and
        # ION's CSP serves no unsafe-eval, so it throws silently.
        for trigger in re.findall(r'hx-trigger="([^"]*)"', body):
            assert "[" not in trigger, trigger
    assert "htmx:responseError" not in src
    assert "htmx:sendError" not in src
    # No inline style attribute anywhere: style-src-attr is 'none'.
    for body in (src, frag):
        assert "style=" not in body


def test_every_oob_slot_carries_the_out_of_band_attribute(monkeypatch):
    """Four slots stay in the shell and are filled out of band.

    Dropping `hx-swap-oob` from one of them is invisible to every other
    test: the fragment still contains the element with its id, so an id
    assertion passes, and the response body still carries the content. Only
    a browser sees the result, which is that slot keeping its spinner
    forever while the rest of the page loads. This asserts the attribute on
    the rendered element rather than anywhere in the file, because the
    fragment's own header comment uses the words "out of band".
    """
    html = call_page(monkeypatch, payload=template())
    for slot in ("template-name", "template-body", "template-variables",
                 "versions-list"):
        found = re.search(rf'<[a-z0-9]+ id="{slot}"[^>]*>', html)
        assert found is not None, f"{slot} not rendered at all"
        assert 'hx-swap-oob="innerHTML"' in found.group(0), (
            f"{slot} is rendered but not out of band, so the shell element "
            f"of that id is never replaced and keeps its spinner"
        )
    # The meta card is the swap target itself and must NOT be out of band.
    assert html.count('hx-swap-oob="innerHTML"') == 4


def test_the_modal_timestamp_goes_through_the_ts_macro(monkeypatch):
    """The modal is the second place this page renders a stored time.

    The table's date is covered. This copy was not, and replacing
    `meta.created(version)` with a raw `{{ version.created_at }}` survived
    the first mutation pass. A raw stamp is a zoneless string that
    local-time.js cannot find and cannot label, so the viewer reads the
    database's clock as their own.
    """
    html = call_version(monkeypatch, one=version(
        created_at=datetime(2026, 10, 12, 14, 51)))
    meta = re.search(r'<div id="version-meta".*?</div>', html, re.S)
    assert meta is not None, "no version-meta bar"
    bar = meta.group(0)
    assert "<time " in bar, bar
    assert "data-ts-local=" in bar
    assert "2026-10-12 14:51" not in bar.replace("<time", "").split(">")[0]


def test_the_tab_panes_do_not_pair_tab_content_with_a_hand_rolled_class():
    """daisyUI 5's `.tab-content` is display:none until the pane's
    immediately preceding sibling is a `.tab` carrying `.tab-active`.

    These buttons sit inside the tablist and carry `.active`, so that rule
    never lifts and a pane carrying `tab-content` is hidden by the
    stylesheet. Measured in a browser before the fix: #content-view
    computed `display: flex` only because the `flex` utility on the same
    element outranks `.tab-content`; removing `flex` alone turned it
    `display: none`. That makes the pairing a trap one utility edit wide,
    which is why the class is gone rather than merely overridden.

    The computed display is not assertable here, which is why the browser
    pass exists. What is assertable is that the pairing has not come back.
    """
    src = _strip(_page())
    panes = {}
    for pane in ("content-view", "variables-view", "versions-view"):
        found = re.search(rf'<div id="{pane}"[^>]*>', src)
        assert found is not None, f"{pane} is not in the page"
        panes[pane] = found.group(0)

    for pane, tag in panes.items():
        assert "tab-content" not in tag, (
            f"{pane} pairs daisyUI's .tab-content with this page's "
            f"hand-rolled .active, so the stylesheet hides it: {tag}"
        )
    # Positive controls: the visible pane keeps its layout classes and the
    # other two are hidden by the class the script toggles.
    assert "flex flex-col gap-4" in panes["content-view"]
    assert "hidden" in panes["variables-view"]
    assert "hidden" in panes["versions-view"]
    assert "hidden" not in panes["content-view"]


def test_the_tab_switch_toggles_hidden_in_the_right_direction():
    """An inverted toggle hides the pane the user just selected.

    Asserted against the script body with line comments stripped, because
    the comment above this line names both `hidden` and the panes.
    """
    js = re.sub(r"//[^\n]*", "", _script(_page()))
    assert "classList.toggle('hidden', name !== view)" in js, js
    assert "classList.toggle('hidden', name === view)" not in js
    assert "classList.toggle('hidden', name !== tab)" in js
    # No pane is positioned by an inline display any more. style-src-attr is
    # 'none', and an assignment would also outrank the class the fragment
    # just sent.
    assert "style.display" not in js


def test_rollback_stays_a_post_and_the_handlers_are_reachable():
    """The mutation stays a mutation. data-click-action looks the function
    up on window, so a function that is not assigned there does nothing
    while every render test stays green."""
    js = _script(_page())
    assert "api.post('/api/templates/' + id + '/rollback/' + versionNum)" in js
    assert "window.rollbackToVersion = rollbackToVersion" in js
    assert "window.switchVersionTab = switchVersionTab" in js
    assert "versionNum === null || versionNum === undefined || versionNum === ''" in js
    assert "new CustomEvent('template-view:changed')" in js


# ---------------------------------------------------------------------------
# The real service, so a stub that drifts from template_payload still fails.
# ---------------------------------------------------------------------------


def _app(session):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    app = FastAPI()
    app.include_router(router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: _User(rollback=True)
    app.dependency_overrides[get_db_session] = lambda: session
    return app


def test_the_route_renders_a_real_template_from_the_service(session):
    """Heading level 0, a variable badge, an escaped tag and the library's
    document-type class, through template_payload and list_versions rather
    than a dict assembled in this file. assemble_jinja2 of a heading at
    level 0 is zero hash marks and must not throw while the template is
    created."""
    from ion.services.section_types import assemble_jinja2
    from ion.services.template_service import TemplateService

    sections = [
        {"type": "heading", "config": {"text": "Scope", "level": 0}},
        {"type": "text", "config": {
            "variable": True, "variable_name": "widget", "content": "unused",
        }},
    ]
    assembled = assemble_jinja2(sections)
    assert "Scope" in assembled
    assert not assembled.startswith("#")

    created = TemplateService(session).create_template(
        name="Probe template view",
        sections=sections,
        tags=["<script>alert(1)</script>"],
        document_type="SOP",
        description="probe",
    )
    session.commit()
    with TestClient(_app(session)) as client:
        resp = client.get(f"/ui/template-view/{created.id}")
        missing = client.get("/ui/template-view/99999")
        absent = client.get(
            f"/ui/template-view/{created.id}/versions/99"
        )
    assert resp.status_code == 200
    text = resp.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "<script>" not in text
    assert "Scope" in text
    assert "Level: H0" in text
    assert "widget" in text
    assert "sv-var-badge" in text
    assert 'id="section-count-badge">2</span>' in text
    assert 'data-doctype="SOP"' in text
    assert "<time " in text
    assert ">Current<" in text
    assert "Initial version" in text
    assert f'/ui/template-view/{created.id}/versions/1' in text

    assert missing.status_code == 200
    assert "There is no template 99999" in missing.text
    assert "No variables detected" not in missing.text
    assert "No version history available" not in missing.text

    assert absent.status_code == 200
    assert "does not exist" in absent.text
    assert "could not be read" not in absent.text


def _bare_app(session, user=None):
    """The router with no auth override, so the real dependencies run.

    The tests above call the handlers directly and so never touch the
    decorator. The permission moved onto the decorator, where
    test_ui_fragment_registry.py can read that it is DECLARED; whether it
    actually refuses a request is this file's job and nothing asserted it.
    """
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    app = FastAPI()
    app.include_router(router, prefix="/ui")
    app.dependency_overrides[get_db_session] = lambda: session
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


class _NoReadUser:
    """A signed-in user who holds neither permission this page names."""

    id = 2
    username = "outsider"

    def has_permission(self, name: str) -> bool:
        return False


@pytest.mark.parametrize("path", [
    "/ui/template-view/1",
    "/ui/template-view/1/versions/1",
])
def test_both_routes_refuse_an_unauthenticated_request(session, path):
    """401, not a render and not a redirect.

    A redirect would be require_page_permission, which htmx would swap into
    the middle of the page as a login form. The registry suite guards that
    no such dependency is declared; this guards what the route answers.
    """
    with TestClient(_bare_app(session)) as client:
        resp = client.get(path, follow_redirects=False)
    assert resp.status_code == 401, resp.text
    assert "template-meta" not in resp.text
    assert "versions-list" not in resp.text


@pytest.mark.parametrize("path", [
    "/ui/template-view/1",
    "/ui/template-view/1/versions/1",
])
def test_both_routes_refuse_a_user_without_the_read_permission(session, path):
    """The declared permission has to bite, not merely be declared.

    This is the assertion that fails if the decorator's dependency is
    deleted. Moving the gate off a parameter default and onto the decorator
    made that deletion a one-line edit which every other test in this file
    survives, because they call the handler function directly and supply the
    User themselves.
    """
    with TestClient(_bare_app(session, _NoReadUser())) as client:
        resp = client.get(path, follow_redirects=False)
    assert resp.status_code == 403, resp.text
    assert "versions-list" not in resp.text


def test_the_rollback_control_is_withheld_without_the_write_permission(session):
    """Read-only viewers get the history and no rollback button.

    Through the real router rather than a direct call, so this covers the
    whole path from the request to the withheld control.
    """
    from ion.services.template_service import TemplateService

    created = TemplateService(session).create_template(
        name="Probe rollback gating", content="one", description="probe",
    )
    # A second version, so there is a non-current row for rollback to be
    # offered on at all. Without it both users would correctly see no
    # button and the test would pass for the wrong reason.
    TemplateService(session).update_template(
        template_id=created.id, content="two", version_message="second",
    )
    session.commit()

    class _ReadOnly(_NoReadUser):
        def has_permission(self, name: str) -> bool:
            return name == PERMISSION

    with TestClient(_bare_app(session, _ReadOnly())) as reader:
        viewer = reader.get(f"/ui/template-view/{created.id}")
    with TestClient(_bare_app(session, _User(rollback=True))) as writer:
        editor = writer.get(f"/ui/template-view/{created.id}")

    assert viewer.status_code == 200
    assert editor.status_code == 200
    # Both see both versions, so a withheld button is not an empty render.
    # Whitespace collapsed first: the cell wraps, so ">v1<" matches nothing
    # and would make this pass for a page that rendered no history at all.
    for body in (viewer.text, editor.text):
        flat = " ".join(body.split())
        assert "<td> v1" in flat, flat[:200]
        assert "<td> v2" in flat
    assert "rollbackToVersion" not in viewer.text
    assert "rollbackToVersion" in editor.text
