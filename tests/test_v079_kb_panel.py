"""v0.79.0 — the SOC workspace Knowledge Base panel actually works.

Three faults, all silent — nothing errored, the panel just quietly did less
than it looked like it did:

  1. **Every result link was dead.** Results have always pointed at
     ``/documents#doc-<id>``, but ``documents.html`` had no hash handling of
     any kind — no ``location.hash`` read, no ``hashchange`` listener. Clicking
     a result dropped the analyst on the unfiltered document list and the
     article they asked for never opened.

  2. **Search ignored the articles.** The endpoint docstring promised "title
     or content"; the query filtered ``Document.name`` alone. Searching for a
     command, a registry key or a technique id found nothing unless it
     happened to appear in a title — ``Invoke-WebRequest`` and ``T1059`` both
     returned zero against a library that contains both many times over.

  3. **The panel was an empty box until you typed.** ~600 articles across ~55
     topics, and no way in for an analyst who did not already know the phrase
     to search for.

The fourth issue was found by clicking the fix rather than reading it: topic
chips first searched for the collection's NAME, which returns nothing, because
"Windows & Active Directory" is a shelf label that appears in no article. A
topic has to be listed by id. `test_topic_chip_lists_by_id_not_by_name` pins
that, and it is the one most likely to regress — searching by name *looks*
right in the diff.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES = Path("src/ion/web/templates")
API = Path("src/ion/web/api.py")


@pytest.fixture(scope="module")
def analyst() -> str:
    return (TEMPLATES / "analyst.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def documents() -> str:
    return (TEMPLATES / "documents.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def api_src() -> str:
    return API.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def search_fn(api_src: str) -> str:
    start = api_src.index("async def search_analyst_knowledge_base")
    rest = api_src[start:]
    return rest[:rest.index("\n@router.")]


@pytest.fixture(scope="module")
def browse_fn(api_src: str) -> str:
    start = api_src.index("async def get_analyst_knowledge_base")
    rest = api_src[start:]
    return rest[:rest.index("\n@router.")]


# ── 1. the click-through works ───────────────────────────────────────────


def test_documents_opens_the_document_named_in_the_hash(documents):
    assert "openDocumentFromHash" in documents
    assert r"/^#doc-(\d+)$/" in documents, "the #doc-<id> pattern is gone"
    assert "viewDocument(id)" in documents


def test_hash_is_handled_on_load_and_on_change(documents):
    """Arriving from another page fires DOMContentLoaded; changing the hash
    while already on /documents fires only hashchange. Both, or half the
    links stay dead."""
    assert "await openDocumentFromHash();" in documents
    assert "window.addEventListener('hashchange', openDocumentFromHash);" in documents


def test_hash_open_happens_after_the_list_loads(documents):
    """Opening the modal over an empty page shows a document with no context
    behind it, and loadDocuments() would clobber it moments later."""
    init = documents[documents.index("document.addEventListener('DOMContentLoaded'"):]
    init = init[:init.index("});")]
    assert init.index("await loadDocuments();") < init.index("await openDocumentFromHash();")


def test_kb_panel_still_links_to_the_hash_route(analyst):
    assert "/documents#doc-${a.id}" in analyst


# ── 2. search covers article text ────────────────────────────────────────


def test_search_covers_content_not_just_titles(search_fn):
    assert "Document.rendered_content.ilike(search_term)" in search_fn
    assert "or_(" in search_fn


def test_content_hits_explain_themselves(search_fn):
    """A content match with no snippet is a title that does not obviously
    contain what was typed — the analyst has to open it to find out why."""
    assert '"matched_in"' in search_fn
    assert '"snippet"' in search_fn


def test_title_matches_rank_above_content_matches(search_fn):
    assert 'results.sort(' in search_fn
    assert 'r["matched_in"] != "title"' in search_fn


def test_search_is_bounded(search_fn):
    """Content ILIKE over the whole library, unbounded, is a page-load hazard
    on a query like 'the'."""
    assert "min(limit, 100)" in search_fn


# ── 3. browse before search ──────────────────────────────────────────────


def test_browse_endpoint_can_skip_the_article_bodies(browse_fn):
    """include_articles=false exists so the panel can render ~55 topic counts
    without shipping ~600 articles to do it."""
    assert "include_articles: bool = True" in browse_fn
    assert "func.count(Document.id)" in browse_fn, "counts are being done with len() over loaded rows"


def test_browse_endpoint_offers_recent_articles(browse_fn):
    assert "recent: int = 0" in browse_fn
    assert 'result["recent"]' in browse_fn
    assert "Document.updated_at.desc()" in browse_fn


def test_panel_loads_browse_on_page_load(analyst):
    assert "loadKBBrowse" in analyst
    assert re.search(r"loadKBBrowse\(\);", analyst)


def test_panel_caps_the_topic_chips(analyst):
    """All ~55 topics as chips buries the rest of the workspace."""
    assert "TOPIC_CHIPS = 12" in analyst
    assert "more</a>" in analyst, "no overflow affordance for the topics that are not shown"


def test_clearing_the_box_returns_to_browsing(analyst):
    fn = analyst[analyst.index("async function doKBSearch"):]
    fn = fn[:fn.index("\nasync function loadKBBrowse")]
    assert "browse.classList.remove('hidden')" in fn
    assert "browse.classList.add('hidden')" in fn


# ── 4. the bug the click test found ──────────────────────────────────────


def test_topic_chip_lists_by_id_not_by_name(analyst):
    """A topic chip that text-searches for its own label returns NOTHING —
    "Windows & Active Directory" is a shelf label and appears in no article.
    This looked correct in the diff and only failed when clicked."""
    assert "data-args='[${c.id}]'" in analyst, "topic chips are passing the collection name again"
    assert "collection_id=" in analyst


def test_search_endpoint_accepts_a_collection_filter(search_fn):
    assert "collection_id: Optional[int] = None" in search_fn
    assert 'q: str = ""' in search_fn, "q must be optional when browsing a collection"


def test_collection_filter_cannot_escape_the_knowledge_base(search_fn):
    """collection_id is client-supplied. Without the membership check it is a
    way to read any collection in the library through a KB endpoint."""
    assert "collection_id in child_ids" in search_fn


def test_empty_query_with_no_collection_returns_nothing(search_fn):
    """Making q optional must not turn a bare call into 'dump the library'."""
    assert "if not q and collection_id is None:" in search_fn
