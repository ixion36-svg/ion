"""v0.79.0 — /documents uses the same inset-overlay workspace as /cases.

Opening a document meant a centred modal whose content sat behind four tabs
(Rendered / Raw / Edit / Version history), so reading an article and checking
what changed in it were never on screen together, and moving to the next
document meant close → find → open. It is now the shape /cases got at v0.77.0:
a 22px inset panel over the dimmed board, the current folder's documents in a
left rail, and every section open in one scroll under sticky jump-links.

Dropping the Knowledge Base exclusion is the other half. `/documents` filtered
out every KB document AND every KB collection, so on a library that is almost
entirely KB the page read "No documents found" and the ~600 articles had no
browsing surface anywhere in ION.

That change surfaced a defect the tabs had hidden: the single-document endpoint
never returned `collection_id`, so anything opening a document directly — the
KB deep-link, this panel — could not say which folder it was in.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES = Path("src/ion/web/templates")
API = Path("src/ion/web/api.py")


@pytest.fixture(scope="module")
def documents() -> str:
    return (TEMPLATES / "documents.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def api_src() -> str:
    return API.read_text(encoding="utf-8")


def _inline_js(html: str) -> str:
    return "\n".join(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S))


def _strip_comments(js: str) -> str:
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    return re.sub(r"^\s*//.*$", "", js, flags=re.M)


# ── the panel is the shared workspace, not a modal ───────────────────────


def test_document_view_uses_the_shared_workspace_chrome(documents):
    for cls in ("ion-ws-overlay", "ion-ws-panel", "ion-ws-header",
                "ion-ws-body workspace-mode", "ion-ws-grid",
                "ion-ws-rail", "ion-ws-detail"):
        assert cls in documents, f"{cls} missing — the panel is not the shared chrome"


def test_the_old_modal_classes_are_gone(documents):
    panel = documents[documents.index('id="document-modal"'):]
    panel = panel[:panel.index("<!-- Amendment")]
    for cls in ('class="modal ', "modal-content", "modal-body", "modal-footer"):
        assert cls not in panel, f"{cls} is back — this is a modal again"


def test_panel_opens_and_closes_by_class_not_display(documents):
    """`display` skips the .open transition the cases panel uses."""
    js = _strip_comments(_inline_js(documents))
    assert "classList.add('open')" in js
    assert "document.getElementById('document-modal').style.display = 'flex'" not in js


def test_click_outside_is_the_overlays_job(documents):
    """The old handler closed when the click landed on #document-modal — which
    used to be the backdrop but is now the PANEL, so it would close whenever
    the analyst clicked its own padding."""
    js = _strip_comments(_inline_js(documents))
    assert "e.target.id === 'document-modal'" not in js
    overlay = documents[documents.index('id="doc-panel-overlay"'):]
    assert 'data-click-action="closeModal"' in overlay[:overlay.index(">")]


# ── stacked sections, not tabs ───────────────────────────────────────────


def test_switch_tab_is_retired(documents):
    js = _strip_comments(_inline_js(documents))
    assert not re.search(r"^function switchTab\b", js, re.M)
    assert 'class="content-tab-btn' not in documents


@pytest.mark.parametrize("section_id", [
    "doc-sec-details", "doc-sec-document", "doc-sec-source",
    "doc-sec-edit", "doc-sec-versions", "modal-doc-data-section",
])
def test_every_view_is_now_a_stacked_section(section_id, documents):
    assert f'id="{section_id}"' in documents
    block = documents[documents.index(f'id="{section_id}"') - 120:]
    assert "iad-section" in block[:200], f"{section_id} is not a stacked section"


def test_jump_links_scroll_rather_than_hide(documents):
    """A jump-link that hides its siblings is a tab wearing a hat — the same
    contract the /cases jump-links hold."""
    js = _strip_comments(_inline_js(documents))
    fn = js[js.index("function docJumpTo"):]
    fn = fn[:fn.index("\n}")]
    assert "scrollIntoView" in fn
    assert "display" not in fn, "docJumpTo is hiding sections instead of scrolling"


def test_versions_load_without_a_click(documents):
    """Version history was behind a tab, so it only loaded if you went looking."""
    js = _strip_comments(_inline_js(documents))
    fn = js[js.index("async function viewDocument"):]
    fn = fn[:fn.index("\nasync function") if "\nasync function" in fn else len(fn)]
    assert "loadVersions();" in fn


# ── the rail ─────────────────────────────────────────────────────────────


def test_rail_lists_the_documents_currently_in_view(documents):
    js = _strip_comments(_inline_js(documents))
    fn = js[js.index("function renderDocRail"):]
    fn = fn[:fn.index("\nfunction ")]
    assert "filterDocuments()" in fn, "the rail ignores the folder and filters"
    assert "data-click-action=\"viewDocument\"" in fn


def test_rail_is_capped_and_says_what_it_dropped(documents):
    """~600 rail rows is a slow panel. Silent truncation reads as 'that is
    everything'."""
    js = _strip_comments(_inline_js(documents))
    fn = js[js.index("function renderDocRail"):]
    fn = fn[:fn.index("\nfunction ")]
    assert "RAIL_MAX" in fn
    assert "hiddenCount" in fn
    assert "more —" in fn


def test_open_document_survives_the_cap(documents):
    """If the open document falls outside the cap it must still appear, or the
    rail shows no selection at all."""
    js = _strip_comments(_inline_js(documents))
    fn = js[js.index("function renderDocRail"):]
    fn = fn[:fn.index("\nfunction ")]
    assert "capped.some(d => d.id === activeId)" in fn


# ── the Knowledge Base is visible ────────────────────────────────────────


def test_knowledge_base_is_no_longer_filtered_out(documents):
    js = _strip_comments(_inline_js(documents))
    assert "allDocuments.filter(d => !kbCollectionIds.has(d.collection_id))" not in js
    assert "allCollections.filter(c => !kbCollectionIds.has(c.id))" not in js


def test_detail_endpoint_returns_the_collection(api_src):
    """The list endpoint returned collection_id; the detail endpoint did not,
    so a document opened directly could not say which folder it was in."""
    fn = api_src[api_src.index("async def get_document("):]
    fn = fn[:fn.index("\n@router.")]
    assert '"collection_id": document.collection_id' in fn
    assert '"created_by_id": document.created_by_id' in fn


# ── delete affordance matches the server rule ────────────────────────────


def test_delete_button_is_hidden_from_users_who_cannot_use_it(documents):
    """Cosmetic — the endpoint enforces it — but without this every analyst
    gets a Delete button on all ~600 articles and a 403 when they press it."""
    js = _strip_comments(_inline_js(documents))
    fn = js[js.index("function updateDeleteVisibility"):]
    fn = fn[:fn.index("\n}")]
    assert "created_by_id" in fn
    assert "document:delete" in fn
