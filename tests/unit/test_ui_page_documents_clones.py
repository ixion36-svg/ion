"""The client-state renders on documents.html, and the three writes that stay.

The rail, the jump nav and the tag chips are built from data the page
already holds, so none of them is a server read. They are template clones
filled with textContent, which is the project's pattern for client state
and which also fixes the third instance of one defect: the tag chips put
`JSON.stringify(tag)` inside a single-quoted attribute, and tags are free
text.

The file also pins the floor. Three writes stay and are meant to, and a
later reader with the measure in hand would otherwise "finish" the page by
escaping a document body.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/documents.html"
SHEET = ROOT / "src/ion/web/static/css/documents-page.css"


def page() -> str:
    """The page with its Jinja comments stripped.

    One of those comments contains the words `<script>` in prose, which is
    what broke the script extractor I used to syntax-check this page: the
    regex matched from inside the comment. Four checks on this project have
    now passed or failed against their own prose.
    """
    return re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)


def fn(name: str, *, code_only: bool = False) -> str:
    """One function's source, optionally with its JavaScript comments gone.

    `code_only` exists because the comments on these functions quote the
    defect they fixed, so an assertion that a pattern is absent matches the
    prose describing it. That has now happened five times on this project,
    once in each direction.
    """
    match = re.search(r"\bfunction " + name + r"\(.*?\n\}", page(), re.S)
    assert match, name + " is still in the page"
    body = match.group(0)
    if code_only:
        body = re.sub(r"//[^\n]*", "", body)
        body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    return body


def templates_block() -> str:
    """Everything outside the script block, where a <template> has to live."""
    body = page()
    scripts = re.findall(r"<script[^>]*>.*?</script>", body, re.S)
    for block in scripts:
        body = body.replace(block, "")
    return body


# ---------------------------------------------------------------------------
# The three writes that stay
# ---------------------------------------------------------------------------


def test_exactly_three_writes_remain_and_they_are_the_document_bodies():
    """ION ships no HTML sanitiser and the decision not to add one is
    recorded in ui/template_render.py. Escaping a document body would make
    this a viewer that does not show documents, so these stay under the
    strict CSP. This asserts the count so a fourth cannot arrive quietly.
    """
    writes = re.findall(r"^.*\.innerHTML\s*=.*$", page(), re.M)
    assert len(writes) == 3, writes
    joined = "\n".join(writes)
    assert "docQuillEditor.root" in joined
    assert "rendered-view" in joined
    assert "version-content" in joined


def test_the_module_records_why_those_three_stay():
    """So the next person with the measure in hand does not escape them."""
    module = (ROOT / "src/ion/web/ui/documents.py").read_text(
        encoding="utf-8")
    assert "no HTML sanitiser" in module
    assert "template_render.py" in module


# ---------------------------------------------------------------------------
# Templates live outside the script block
# ---------------------------------------------------------------------------


CLONED = ("doc-rail-item", "doc-rail-overflow", "doc-jump-link",
          "doc-tag-chip", "doc-tags-empty")


@pytest.mark.parametrize("ident", CLONED)
def test_each_template_is_outside_the_script_block(ident):
    """A <template> inside a <script> is inert text and clones to nothing,
    with no error anywhere."""
    assert 'id="' + ident + '"' in templates_block(), ident


@pytest.mark.parametrize("ident", CLONED)
def test_each_template_is_actually_cloned(ident):
    assert "cloneDocTemplate('" + ident + "')" in page(), ident


# ---------------------------------------------------------------------------
# What the clones fill, and how
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["renderDocRail", "renderDocJump",
                                  "renderDocumentTags"])
def test_the_client_renders_parse_no_strings(name):
    body = fn(name)
    assert not re.search(r"\.innerHTML\s*=", body), name
    assert "cloneDocTemplate" in body, name
    assert "textContent" in body, name


def test_the_rail_sets_its_argument_as_an_attribute():
    """`data-args='[${d.id}]'` by interpolation could produce JSON that
    JSON.parse throws on, which event-delegation.js logs and returns from."""
    body = fn("renderDocRail")
    assert "setAttribute('data-args', JSON.stringify([d.id]))" in body


def test_the_rail_does_not_claim_version_one():
    """`v${d.current_version || 1}` named a revision it did not have."""
    body = fn("renderDocRail")
    assert "Number.isInteger(d.current_version)" in body
    assert "version unknown" in body


def test_the_tag_chip_sets_its_argument_as_an_attribute():
    """The third place this page built data-args with JSON.stringify inside
    a single-quoted attribute. JSON.stringify escapes " and not ', so a tag
    with an apostrophe closed it early and the remove control did nothing.
    """
    body = fn("renderDocumentTags", code_only=True)
    assert "setAttribute('data-args', JSON.stringify([tag]))" in body
    assert "JSON.stringify(tag)" not in body, (
        "the old form is gone from the code; the comment still quotes it")


def test_the_tag_list_survives_a_tags_value_that_is_not_a_list():
    """`currentDocTags.length` threw, and renderDocumentTags is called from
    viewDocument's try, so the whole modal read as a failed load."""
    assert "Array.isArray(currentDocTags)" in fn("renderDocumentTags")


# ---------------------------------------------------------------------------
# The busy state
# ---------------------------------------------------------------------------


def test_the_export_button_has_a_label_element_to_change():
    """Writing textContent on the button itself would drop its icon."""
    assert "data-btn-label" in templates_block()
    assert "[data-btn-label]" in page()


def test_the_busy_spinner_is_in_the_stylesheet():
    """It was `<i class="icon-loader"></i>` in a JavaScript string, so the
    spinner was markup the page owned and a stylesheet could not reach."""
    sheet = SHEET.read_text(encoding="utf-8")
    assert ".is-busy" in sheet
    assert "@keyframes doc-busy-spin" in sheet


def test_the_spinner_respects_reduced_motion():
    sheet = SHEET.read_text(encoding="utf-8")
    assert "prefers-reduced-motion" in sheet


# ---------------------------------------------------------------------------
# The local helper, and why it is local
# ---------------------------------------------------------------------------


def test_the_clone_helper_is_defined_on_this_page_with_its_reason():
    """static/js/ion-fragments.js has one and also sets
    htmx.config.useTemplateFragments for the whole page, which is a
    behaviour change this page does not need."""
    body = page()
    assert "function cloneDocTemplate(" in body
    assert "useTemplateFragments" in body, (
        "the comment names the side effect that kept it local")
    # The claim is that the file is not loaded, not that it is never
    # mentioned: the comment above the helper names it on purpose.
    assert not re.search(r'src="[^"]*ion-fragments\.js', body), (
        "the shared file is not loaded here")


# ---------------------------------------------------------------------------
# The stylesheet left the page
# ---------------------------------------------------------------------------


def test_the_page_has_no_inline_style_block():
    assert "<style" not in page()


def test_the_sheet_still_beats_what_the_block_beat_that_matters():
    """The block sat at the end of <body> and beat every stylesheet. From
    head_css it loses to ion-workspace.css and base.html's two in-body
    blocks, so the move is only safe while none of the block's selectors
    appears in those three. Measured as zero before the move; asserted here
    so adding one is a failing test rather than a silent restyle."""
    sheet = SHEET.read_text(encoding="utf-8")
    selectors = set()
    for match in re.finditer(r"(^|\})\s*([^{}@][^{}]*?)\s*\{", sheet, re.M):
        for part in match.group(2).split(","):
            part = part.strip()
            if part and not part.startswith("/*"):
                selectors.add(part)
    assert len(selectors) > 50, len(selectors)

    workspace = (ROOT / "src/ion/web/static/css/ion-workspace.css").read_text(
        encoding="utf-8", errors="replace")
    base = (ROOT / "src/ion/web/templates/base.html").read_text(
        encoding="utf-8")
    base_blocks = "\n".join(
        re.findall(r"<style[^>]*>(.*?)</style>", base, re.S))
    clashes = sorted(s for s in selectors
                     if s in workspace or s in base_blocks)
    assert not clashes, clashes


def test_the_page_links_the_sheet_from_head_css():
    head = re.search(r"\{%\s*block head_css\s*%\}(.*?)\{%\s*endblock\s*%\}",
                     PAGE.read_text(encoding="utf-8"), re.S)
    assert head, "linked from head_css"
    assert "documents-page.css" in head.group(1)
