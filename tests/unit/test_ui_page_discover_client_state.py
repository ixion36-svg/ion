"""What discover.html still does in the browser, and how.

`dscLoadCaseOptions` filled the pin-to-case picker with three
`select.innerHTML = '<option ...>'` writes. An <option> is not markup a
stylesheet sweep has to reach, so the redesign's reason for moving markup
to the server does not apply to it: what it needed was the DOM call that
does the same job without parsing a string.

It also had a defect worth the visit. `const cases = data.cases || data ||
[]` fell through to `data` when `data.cases` was absent, and a payload that
was neither an array nor an object with a `cases` array then reached
`.length` of undefined, which is falsey, so the picker read "No open
cases". That says we looked and there are none.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/discover.html"


def page() -> str:
    return re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)


def fn(name: str, *, code_only: bool = False) -> str:
    """One function's source, optionally without its JavaScript comments.

    The comments quote the defects they fixed, so an assertion that a
    pattern is absent otherwise matches the prose describing it.
    """
    match = re.search(r"\bfunction " + name + r"\(.*?\n\}", page(), re.S)
    assert match, name + " is still in the page"
    body = match.group(0)
    if code_only:
        body = re.sub(r"//[^\n]*", "", body)
        body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    return body


def test_the_case_picker_parses_no_strings():
    body = fn("dscLoadCaseOptions", code_only=True)
    assert not re.search(r"\.innerHTML\s*=", body)
    assert "createElement('option')" in body
    assert "textContent" in body


def test_the_helper_clears_before_it_adds():
    helper = fn("dscOnlyOption")
    assert "replaceChildren(opt)" in helper
    assert "textContent" in helper
    assert not re.search(r"\.innerHTML\s*=", helper)


def test_the_helper_survives_a_missing_select():
    assert "if (!select) return;" in fn("dscOnlyOption")


def test_a_payload_of_neither_shape_is_told_apart_from_an_empty_one():
    """The defect. `data.cases || data || []` made them one answer."""
    body = fn("dscLoadCaseOptions")
    assert "Array.isArray(data)" in body
    assert "Array.isArray(data.cases)" in body
    assert "Could not read the case list" in body
    assert "No open cases" in body


def test_the_three_outcomes_are_three_different_sentences():
    body = fn("dscLoadCaseOptions")
    sentences = {
        "Could not read the case list",   # a body we could not read
        "No open cases",                  # read, and there are none
        "Could not load cases",           # the request itself failed
    }
    for sentence in sentences:
        assert sentence in body, sentence
    assert len(sentences) == 3


def test_a_case_without_an_id_is_skipped_rather_than_offered():
    """`value="undefined"` is an option that selects nothing and reports a
    case id of the string undefined to whatever reads it."""
    body = fn("dscLoadCaseOptions", code_only=True)
    assert "c.id === undefined" in body


def test_the_option_label_is_text_not_escaped_markup():
    """`escapeHtml(...)` inside a built string was doing by hand what
    textContent does by definition."""
    body = fn("dscLoadCaseOptions", code_only=True)
    assert "escapeHtml" not in body
