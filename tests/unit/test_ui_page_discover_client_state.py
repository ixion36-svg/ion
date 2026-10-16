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


# ---------------------------------------------------------------------------
# The provenance block and the AI query modal
# ---------------------------------------------------------------------------


def test_the_provenance_block_is_text_not_escaped_markup():
    """It is a plain-text block and its container carries
    whitespace-pre-wrap, so the page was escaping each half by hand and
    then writing the result as innerHTML: escaping for a string that was
    never going to be parsed as markup."""
    body = fn("dscRenderProvenance", code_only=True)
    assert not re.search(r"\.innerHTML\s*=", body)
    assert "textContent" in body
    assert "escapeHtml" not in body


def test_the_provenance_container_still_renders_newlines():
    """textContent only works here because the container preserves them."""
    page_text = page()
    container = re.search(r'id="pin-query-provenance"[^>]*', page_text)
    assert container, "the container"
    assert "whitespace-pre-wrap" in container.group(0)


def test_the_ai_query_modal_is_in_the_page_not_built_from_a_string():
    body = fn("openNlQueryModal", code_only=True)
    assert not re.search(r"\.innerHTML\s*=", body)
    assert "createElement" not in body
    assert 'id="nl-query-modal"' in page(), "it lives in the markup"


def test_the_modal_markup_is_inside_the_content_block():
    """Outside a block it would not render at all, and the first
    `{% endblock %}` on this page closes the title."""
    body = page()
    modal = body.index('id="nl-query-modal"')
    content = body.index("{% block content %}")
    scripts = body.index("{% block scripts %}")
    assert content < modal < scripts


def test_the_modal_colours_are_in_the_stylesheet():
    """They were text-[#f87171], bg-[#1e293b] and text-[#e2e8f0] inside a
    JavaScript template string."""
    sheet = (ROOT / "src/ion/web/static/css/discover-page.css").read_text(
        encoding="utf-8")
    assert ".dsc-nl-error" in sheet
    assert ".dsc-nl-output" in sheet
    body = page()
    for gone in ("text-[#f87171]", "bg-[#1e293b]", "text-[#e2e8f0]"):
        assert gone not in body, gone


def test_the_modal_is_shown_and_hidden_by_one_mechanism():
    """Its inner elements already carry `hidden` in the markup, so
    style.display was a second opinion on the same question."""
    body = page()
    for name in ("openNlQueryModal", "closeNlQueryModal"):
        assert "style.display" not in fn(name), name
    assert "classList.remove('hidden')" in fn("openNlQueryModal")
    assert "classList.add('hidden')" in fn("closeNlQueryModal")


def test_the_enter_listener_is_bound_at_load_not_at_first_open():
    """It was attached inside the builder, so it existed only after the
    first open and only on that one element."""
    body = page()
    assert "e.target.id === 'nl-question'" in body
    opener = fn("openNlQueryModal")
    assert "addEventListener" not in opener


def test_the_page_has_no_inline_style_block():
    assert "<style" not in page()


def test_the_page_links_its_stylesheet_from_head_css():
    head = re.search(r"\{%\s*block head_css\s*%\}(.*?)\{%\s*endblock\s*%\}",
                     PAGE.read_text(encoding="utf-8"), re.S)
    assert head, "linked from head_css"
    assert "discover-page.css" in head.group(1)


def test_nothing_that_outranks_the_sheet_claims_its_selectors():
    """head_css loses to ion-workspace.css and to ion-shell.css at equal
    specificity. ion-shell.css is the two blocks that used to sit in
    base.html's body, linked after ion-workspace, so an overlap is a rule
    that is present and never wins. Measured as empty before the move;
    asserted so adding one is a failing test rather than a silent restyle."""
    sheet = (ROOT / "src/ion/web/static/css/discover-page.css").read_text(
        encoding="utf-8")
    selectors = set()
    for match in re.finditer(r"(^|\})\s*([^{}@][^{}]*?)\s*\{", sheet, re.M):
        for part in match.group(2).split(","):
            part = part.strip()
            if part and not part.startswith("/*"):
                selectors.add(part)
    assert len(selectors) > 50, len(selectors)
    workspace = (ROOT / "src/ion/web/static/css/ion-workspace.css").read_text(
        encoding="utf-8", errors="replace")
    shell = (ROOT / "src/ion/web/static/css/ion-shell.css").read_text(
        encoding="utf-8")
    clashes = sorted(s for s in selectors
                     if s in workspace or s in shell)
    assert not clashes, clashes
