"""The add-annotation form starts closed, and its toggle agrees with that.

The form was built by `renderAnnotationFormHtml` as a string, and that
string gave it `class="hidden mt-[0.6rem]"`. The fragment that replaced
the renderer kept the margin and dropped the `hidden`, so the form
rendered open and the first click on "+ Add annotation" set
`display:none` and closed it. Nothing failed, because the only thing that
knew the form started closed was a class in a string literal.

The toggle is a class now rather than `style.display`. A declaration the
browser writes into an element is one no stylesheet sweep reaches, which
is the same reason the rest of this page stopped doing it, and reading the
class back is how the initial state and the toggle can be checked against
each other at all.

`editAnnotation` read the body text with `querySelectorAll('div')[1]`.
That index was the shape of the deleted string. It is a named hook now,
so the fragment can gain a wrapper without silently prefilling the edit
prompt with the header's timestamp.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/cases.html"
FRAGMENT = ROOT / "src/ion/web/templates/_fragments/cases_detail_annotations.html"
COMPILED_CSS = ROOT / "src/ion/web/static/css/ion.css"


def _scripts() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"), flags=re.S)
    scripts = "\n".join(
        re.findall(r"<script[^>]*>(.*?)</script>", body, re.S))
    return re.sub(r"//[^\n]*", "", scripts)


def _function(name: str) -> str:
    match = re.search(
        r"\n(?:async )?function " + re.escape(name) + r"\(.*?\n\}", _scripts(),
        re.S)
    assert match, name
    return match.group(0)


# ---------------------------------------------------------------------------
# The initial state
# ---------------------------------------------------------------------------


def test_the_form_renders_closed():
    """The regression itself. Without this class the form is open on load
    and the add button closes it."""
    fragment = FRAGMENT.read_text(encoding="utf-8")
    form = re.search(r'<div class="([^"]*)"[^>]*id="annotation-form-', fragment)
    assert form, "the form div moved"
    assert "hidden" in form.group(1).split(), form.group(1)


def test_the_class_that_closes_it_exists_in_the_compiled_sheet():
    """`hidden` is Tailwind's, and Tailwind is precompiled here, so a class
    that was never emitted would leave the form open with the markup
    looking right."""
    assert ".hidden{display:none}" in COMPILED_CSS.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The toggle
# ---------------------------------------------------------------------------


def test_the_toggle_uses_the_same_class_the_fragment_renders():
    toggle = _function("toggleAnnotationForm")
    assert "hidden" in toggle
    assert "classList" in toggle


def test_the_toggle_does_not_write_an_inline_display():
    """`style.display` cannot be read back from CSS and cannot be checked
    against the rendered class, which is how the two fell out of step."""
    toggle = _function("toggleAnnotationForm")
    assert "style.display" not in toggle


def test_nothing_else_writes_the_form_closed_with_an_inline_display():
    """`loadAnnotations` ended with

        body.querySelectorAll('[data-annotation-form]')
            .forEach(form => form.style.display = 'none')

    which closed the form after every load and was how the fragment got
    away with dropping `hidden`. An inline declaration beats a class, so
    with the class restored this line would have made the form impossible
    to open: the toggle removes `hidden` and the inline `display:none`
    stays. Two writers of one state, in two mechanisms that do not
    compose.
    """
    body = _scripts()
    for line in body.split("\n"):
        if "data-annotation-form" in line or "annotation-form-" in line:
            assert "style.display" not in line, line.strip()


def test_the_timestamp_is_prefilled_only_when_the_form_opens():
    """Prefilling on the way closed would overwrite nothing visible, but
    it also told us the branch was reading the old inline display."""
    toggle = _function("toggleAnnotationForm")
    assert "ann-ts-" in toggle
    assert "getTimezoneOffset" in toggle


# ---------------------------------------------------------------------------
# The edit prompt's hook
# ---------------------------------------------------------------------------


def test_the_edit_prompt_reads_a_named_hook_not_a_div_index():
    edit = _function("editAnnotation")
    assert "querySelectorAll('div')" not in edit
    assert "data-annotation-body" in edit


def test_the_fragment_carries_that_hook():
    assert "data-annotation-body" in FRAGMENT.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The renderers the fragment replaced
# ---------------------------------------------------------------------------


def test_the_string_renderers_are_gone():
    """Both were unreferenced once the fragment landed, and
    renderAnnotationCard held the page's last
    `new Date(iso).toLocaleString()`, which reads a naive UTC column in the
    viewer's zone."""
    body = _scripts()
    assert "renderAnnotationFormHtml" not in body
    assert "renderAnnotationCard" not in body


def test_the_page_formats_no_instant_in_the_browsers_zone():
    body = _scripts()
    assert "toLocaleString()" not in body
    assert "toLocaleDateString()" not in body
