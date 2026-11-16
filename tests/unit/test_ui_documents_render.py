"""documents.html renders stored document content safely.

STORED CROSS-USER XSS IN THE HTML BRANCH

    case 'html':
        return content; // Already HTML

`renderContent`'s other three branches sanitize or escape. This one
returned the stored column untouched, and both callers assigned the
result to `innerHTML`:

    document.getElementById('rendered-view').innerHTML =
        renderContent(doc.rendered_content, doc.output_format);

`models/document.py` records who may write that column: "Everyone can
read and add documents". So any authenticated user could store a document
with `output_format` of html and have it run in every other user's
session. ION has no server-side HTML sanitiser in its dependencies, which
is what `ui/template_render.py` records, so nothing upstream was removing
it either.

chat.html had the identical branch and the identical comment above it.
That one was fixed; this one was not found at the same time.

THE QUILL SEED

    docQuillEditor.root.innerHTML = htmlContent;

Quill keeps its own model of the document and reads it back on every
edit. Writing its root element directly leaves that model describing the
previous contents, which is why Quill documents
`clipboard.dangerouslyPasteHTML` for exactly this. The read on the next
line, `docQuillInitialHtml = docQuillEditor.root.innerHTML`, stays: it is
the baseline the amendment modal compares against to decide whether
anything changed.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/documents.html"


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
# The security fix
# ---------------------------------------------------------------------------


def test_the_html_branch_sanitises():
    """The finding itself. A document another user stored must not reach
    the DOM as markup the browser trusts."""
    render = _function("renderContent")
    assert "safeHtml(content)" in render


def test_no_branch_returns_the_stored_column_untouched():
    """`return content` in a renderer that feeds innerHTML is the shape of
    the bug, whichever branch it sits in."""
    render = _function("renderContent")
    for line in render.split("\n"):
        assert line.strip() != "return content;", line


def test_every_branch_of_the_dispatch_is_accounted_for():
    """Four formats, four treatments: markdown sanitises through
    safeMarkdown, html through safeHtml, csv escapes each cell, and the
    default escapes the whole string. A fifth branch added without one of
    these is the hole reopening."""
    render = _function("renderContent")
    assert "renderMarkdown(content)" in render
    assert "safeHtml(content)" in render
    assert "renderCSV(content)" in render
    assert "escapeHtml(content)" in render


def test_the_csv_renderer_still_escapes_every_cell():
    csv = _function("renderCSV")
    assert "escapeHtml(cell.trim())" in csv


# ---------------------------------------------------------------------------
# The sinks
# ---------------------------------------------------------------------------


def test_the_page_writes_no_markup_at_runtime():
    writes = re.findall(
        r"[^\n]*(?:innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=)[^\n]*",
        _scripts())
    assert writes == [], writes


def test_both_rendered_views_go_through_the_node_helper():
    body = _scripts()
    assert body.count("ionSetSafeHtml(") == 2
    for call in re.findall(r"ionSetSafeHtml\(([^;]*)\);", body):
        assert "renderContent(" in call, call


# ---------------------------------------------------------------------------
# Quill
# ---------------------------------------------------------------------------


def test_the_editor_is_seeded_through_quills_own_api():
    body = _scripts()
    assert "dangerouslyPasteHTML" in body
    assert "docQuillEditor.root.innerHTML =" not in body


def test_the_change_baseline_still_reads_the_editor_root():
    """A read, not a write. Losing it would make the amendment modal
    treat every open as a change."""
    body = _scripts()
    assert "docQuillInitialHtml = docQuillEditor.root.innerHTML" in body
    assert "pendingAmendmentContent === docQuillInitialHtml" in body
