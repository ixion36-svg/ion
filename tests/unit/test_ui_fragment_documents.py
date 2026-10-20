"""The documents list as a fragment.

Every test drives the route through TestClient with the service the route
calls monkeypatched. The template is never rendered with a hand-built
context.

Measured on documents.html before the change, by reading loadDocuments and
renderDocuments:

  * The Delete button was rendered for every row. `DELETE
    /api/documents/{id}` gates on `document:read`, which everyone holds,
    because the real rule is ownership and it is enforced in the handler
    against the loaded row: your own document, or anyone's with
    `document:delete`. So a reader who owns nothing saw a Delete button on
    every row and got a 403 from each one. The gate is right and the page
    never asked.

  * ``data-args='[${d.id}, ${JSON.stringify(d.name)}]'`` for Delete.
    `JSON.stringify` escapes `"` and leaves `'` alone, and the attribute is
    single quoted, so a document called `Bob's SOP` closed the attribute
    early and the control silently did nothing. Live defect, not a
    hypothetical: document names are free text.

  * ``data-args='[${d.id}, ${d.collection_id || 'null'}]'`` for Move. The
    `|| 'null'` cannot tell a document in no folder from one whose folder
    id the payload did not carry.

  * `(d.current_version || 1)` printed "v1" for a document whose version
    was missing, which is a confident claim about which revision you are
    looking at.

  * `d.output_format` and `d.source_template_version` went in unguarded, so
    a payload missing either printed the word "undefined" in a badge.

  * `formatDate` in static/js/app.js is `new Date(iso).toLocaleDateString()`
    on `isoformat()` of a naive UTC column, so every date on this page was
    the viewer's local reading of a UTC value. Fourth page with this.

  * The folder badge came from a client-side lookup in `allCollections`,
    a second read, so a failed collections read silently removed every
    folder badge. The documents payload already carries `collection_name`.
"""
from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui.documents import DELETE_ANY, PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
SHEET = ROOT / "src/ion/web/static/css/documents-page.css"
PAGE = ROOT / "src/ion/web/templates/documents.html"

URL = "/ui/documents/list"


class _User:
    username = "docs-tester"

    def __init__(self, *permissions, uid=1):
        self.id = uid
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _app(user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: None
    return application


def _get(user, accept=None):
    headers = {"accept": accept} if accept else None
    with TestClient(_app(user)) as client:
        return client.get(URL, headers=headers)


def _reader(*extra, uid=1):
    return _User(PERMISSION, *extra, uid=uid)


class _Doc:
    """What RenderService.list_documents returns: a model, not the JSON."""

    def __init__(self, **kw):
        defaults = {
            "id": 3, "name": "Incident SOP", "output_format": "pdf",
            "source_template_id": 7, "source_template_version": 2,
            "current_version": 4, "status": "active", "collection_id": 2,
            "tags": [], "created_at": "2026-09-01T10:30:00",
            "created_by_id": 1,
        }
        defaults.update(kw)
        for k, v in defaults.items():
            setattr(self, k, v)
        self.collection = type("C", (), {"name": kw.get(
            "_folder", "Runbooks")})() if kw.get("_folder", "Runbooks") else None
        self.source_template = type("T", (), {"document_type": kw.get(
            "_doc_type", "SOP")})() if kw.get("_doc_type", "SOP") else None


@pytest.fixture
def answers(monkeypatch):
    def set(docs=None, raises=None):
        def listing(self, template_id=None, output_format=None):
            if raises is not None:
                raise raises
            return docs

        monkeypatch.setattr(
            "ion.services.render_service.RenderService.list_documents",
            listing)

    return set


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


# ---------------------------------------------------------------------------
# Gate and the three outcomes
# ---------------------------------------------------------------------------


def test_the_list_needs_the_pages_own_permission(answers):
    answers(docs=[])
    assert _get(_User(uid=1)).status_code == 403
    assert _get(_reader()).status_code == 200


def test_a_read_that_raised_says_unavailable_not_empty(answers):
    answers(raises=RuntimeError("the repository fell over"))
    body = flat(_get(_reader()).text)
    assert "Documents unavailable" in body
    assert "No documents found" not in body


@pytest.mark.parametrize("docs", [None, "three", {}, 7])
def test_a_result_that_is_not_a_list_is_unreadable_not_empty(answers, docs):
    answers(docs=docs)
    body = flat(_get(_reader()).text)
    assert "Documents unavailable" in body, docs
    assert "No documents found" not in body, docs


def test_an_empty_library_says_so(answers):
    answers(docs=[])
    body = flat(_get(_reader()).text)
    assert "No documents found" in body
    assert "Documents unavailable" not in body


def test_a_row_renders_its_name_folder_and_type(answers):
    answers(docs=[_Doc()])
    html = _get(_reader()).text
    body = flat(html)
    assert "Incident SOP" in body
    assert "Runbooks" in body, "collection_name comes with the payload"
    assert 'data-doctype="SOP"' in html, "the type chip reads the scale"
    assert "v4" in body
    assert "pdf" in body


def test_an_entry_that_is_not_a_document_is_skipped_not_fatal(answers):
    answers(docs=["junk", _Doc()])
    body = flat(_get(_reader()).text)
    assert "Incident SOP" in body
    assert "Documents unavailable" not in body


# ---------------------------------------------------------------------------
# Ownership decides the Delete control
# ---------------------------------------------------------------------------


def test_the_owner_sees_delete(answers):
    answers(docs=[_Doc(created_by_id=1)])
    assert "deleteDocument" in _get(_reader(uid=1)).text


def test_a_holder_of_delete_any_sees_delete_on_someone_elses(answers):
    answers(docs=[_Doc(created_by_id=99)])
    assert "deleteDocument" in _get(_reader(DELETE_ANY, uid=1)).text


def test_a_reader_who_owns_nothing_does_not_see_delete(answers):
    """The defect. The endpoint would refuse them, and the page offered the
    button anyway, so every click was a 403."""
    answers(docs=[_Doc(created_by_id=99)])
    html = _get(_reader(uid=1)).text
    assert "Incident SOP" in flat(html), "the row still renders"
    assert "deleteDocument" not in html


def test_an_unowned_document_is_not_everyones_to_delete(answers):
    """Documents predating created_by_id have no owner, and the handler
    sends those to the document:delete branch."""
    answers(docs=[_Doc(created_by_id=None)])
    assert "deleteDocument" not in _get(_reader(uid=1)).text
    assert "deleteDocument" in _get(_reader(DELETE_ANY, uid=1)).text


# ---------------------------------------------------------------------------
# The attribute that broke on an apostrophe
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "Bob's SOP",
    'The "quoted" runbook',
    "back\\slash",
    "<script>alert(1)</script>",
])
def test_a_name_with_punctuation_still_yields_parseable_args(answers, name):
    answers(docs=[_Doc(name=name, created_by_id=1)])
    html = _get(_reader(uid=1)).text
    found = re.findall(r"data-args='([^']*)'", html)
    assert found, name
    for raw in found:
        json.loads(unescape(raw))


def test_a_name_with_an_apostrophe_is_not_cut_short(answers):
    """`JSON.stringify` escapes " and not ', and the attribute was single
    quoted, so this name closed it early and the control did nothing."""
    answers(docs=[_Doc(name="Bob's SOP", created_by_id=1)])
    body = flat(_get(_reader(uid=1)).text)
    assert "Bob's SOP" in body


def test_a_document_in_no_folder_is_not_confused_with_an_unknown_folder(
        answers):
    answers(docs=[_Doc(collection_id=None, _folder=None)])
    html = _get(_reader()).text
    for raw in re.findall(r"data-args='([^']*)'", html):
        json.loads(unescape(raw))
    assert "Runbooks" not in flat(html)


# ---------------------------------------------------------------------------
# Numbers and dates
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [None, "latest", {}])
def test_a_missing_version_does_not_claim_v1(answers, value):
    answers(docs=[_Doc(current_version=value)])
    body = flat(_get(_reader()).text)
    assert "Incident SOP" in body
    assert "v1" not in body


def test_a_genuine_version_one_reads_as_v1(answers):
    answers(docs=[_Doc(current_version=1)])
    assert "v1" in flat(_get(_reader()).text)


def test_a_missing_output_format_prints_no_word_undefined(answers):
    answers(docs=[_Doc(output_format=None)])
    body = flat(_get(_reader()).text)
    assert "Incident SOP" in body
    assert "undefined" not in body
    assert "None" not in body


def test_the_created_date_is_read_as_utc_and_says_so(answers):
    """formatDate did `new Date(iso)` on a naive UTC column, so the date was
    the viewer's local reading of it."""
    answers(docs=[_Doc(created_at="2026-09-01T10:30:00")])
    assert "2026-09-01 10:30 UTC" in flat(_get(_reader()).text)


@pytest.mark.parametrize("value", [None, "", "not a date"])
def test_an_unreadable_date_does_not_invent_one(answers, value):
    answers(docs=[_Doc(created_at=value)])
    body = flat(_get(_reader()).text)
    assert "Incident SOP" in body
    assert "UTC" not in body
    assert "1970" not in body


# ---------------------------------------------------------------------------
# Archived state
# ---------------------------------------------------------------------------


def test_an_archived_document_says_so_and_offers_restore(answers):
    answers(docs=[_Doc(status="archived", created_by_id=1)])
    html = _get(_reader(uid=1)).text
    assert "Archived" in flat(html)
    assert "restoreDocument" in html
    assert "archiveDocument" not in html


def test_an_active_document_offers_archive(answers):
    answers(docs=[_Doc(status="active", created_by_id=1)])
    html = _get(_reader(uid=1)).text
    assert "archiveDocument" in html
    assert "restoreDocument" not in html


# ---------------------------------------------------------------------------
# CSP and colours
# ---------------------------------------------------------------------------


def test_the_fragment_has_no_inline_style_or_javascript_url(answers):
    answers(docs=[_Doc()])
    html = _get(_reader()).text
    assert "Incident SOP" in flat(html)
    assert not re.search(r'\sstyle="', html)
    assert "javascript:" not in html


def test_the_fragment_ships_no_colour_of_its_own(answers):
    answers(docs=[_Doc()])
    html = _get(_reader()).text
    assert 'data-doctype="SOP"' in html
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", html)
    assert "rgba(" not in html
    assert "var(--" not in html


def test_the_stylesheet_paints_the_classes_the_fragment_emits():
    sheet = SHEET.read_text(encoding="utf-8")
    for cls in (".doc-row", ".doc-row-archived", ".doc-unmeasured"):
        assert cls in sheet, cls


# ---------------------------------------------------------------------------
# One object, rendered either way
# ---------------------------------------------------------------------------


def test_the_route_answers_json_when_asked_for_json_only(answers):
    answers(docs=[_Doc()])
    body = _get(_reader(), accept="application/json").json()
    assert body["rows"][0]["name"] == "Incident SOP"
    assert body["rows"][0]["version"] == 4
    assert body["rows"][0]["may_delete"] is True


def test_an_unreadable_read_is_visible_in_the_json_too(answers):
    answers(docs="three")
    assert _get(_reader(), accept="application/json").json()["rows"] is None


# ---------------------------------------------------------------------------
# The page no longer builds this list itself
# ---------------------------------------------------------------------------


def test_the_page_no_longer_writes_the_document_list():
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    block = re.search(r"\bfunction loadDocuments\(.*?\n\}", body, re.S)
    assert block, "the loader is still there to drive the list"
    assert not re.search(r"\.innerHTML\s*=", block.group(0))

    # renderDocuments keeps its name, because a dozen places call it after a
    # change and rewiring each one would be a bigger diff than the
    # conversion. What has to be gone is the string building.
    builder = re.search(r"\bfunction renderDocuments\(.*?\n\}", body, re.S)
    assert builder, "the re-render entry point"
    assert "htmx.ajax" in builder.group(0)
    assert "/ui/documents/list" in builder.group(0)
    assert not re.search(r"\.innerHTML\s*=", builder.group(0))
    for gone in ("list-item-actions", "JSON.stringify(d.name)",
                 "doc-type-badge", "collection-badge"):
        assert gone not in builder.group(0), gone

    # The five controls reach the route by name, so the filter the server
    # applies is the filter the page shows.
    query = re.search(r"\bfunction documentFilterQuery\(.*?\n\}", body, re.S)
    assert query, "the filter is handed over, not reimplemented"
    for control in ("search-input", "format-filter", "status-filter",
                    "tag-filter", "folder"):
        assert control in query.group(0), control


# ---------------------------------------------------------------------------
# The filter, which used to run in the browser over a capped list
# ---------------------------------------------------------------------------


def _q(user, **params):
    from urllib.parse import urlencode
    with TestClient(_app(user)) as client:
        return client.get(URL + "?" + urlencode(params))


def test_search_matches_on_the_name(answers):
    answers(docs=[_Doc(id=1, name="Incident SOP"),
                  _Doc(id=2, name="Firewall change")])
    body = flat(_q(_reader(), search="firewall").text)
    assert "Firewall change" in body
    assert "Incident SOP" not in body


def test_search_is_case_insensitive_as_it_was(answers):
    answers(docs=[_Doc(name="Incident SOP")])
    assert "Incident SOP" in flat(_q(_reader(), search="incident").text)


def test_a_document_with_no_name_does_not_take_the_list_down(answers):
    """`d.name.toLowerCase()` threw, and the throw landed in loadDocuments'
    catch, so one nameless document rendered the whole list as "Failed to
    load documents"."""
    answers(docs=[_Doc(id=1, name=None), _Doc(id=2, name="Firewall change")])
    body = flat(_q(_reader(), search="firewall").text)
    assert "Firewall change" in body
    assert "Documents unavailable" not in body


def test_a_search_that_matches_nothing_is_empty_not_unavailable(answers):
    """The distinction the whole fragment turns on: filtered to nothing is
    not the same as unreadable."""
    answers(docs=[_Doc(name="Incident SOP")])
    body = flat(_q(_reader(), search="nothing-like-this").text)
    assert "No documents found" in body
    assert "Documents unavailable" not in body


def test_the_format_and_status_filters_apply(answers):
    answers(docs=[_Doc(id=1, output_format="pdf", status="active"),
                  _Doc(id=2, output_format="docx", status="archived")])
    assert "docx" in flat(_q(_reader(), format="docx").text)
    assert "pdf" not in flat(_q(_reader(), format="docx").text)
    assert "Archived" in flat(_q(_reader(), status="archived").text)


def test_the_tag_filter_applies(answers):
    class _T:
        def __init__(self, n): self.name = n
    answers(docs=[_Doc(id=1, name="Tagged", tags=[_T("ir")]),
                  _Doc(id=2, name="Untagged", tags=[])])
    body = flat(_q(_reader(), tag="ir").text)
    assert "Tagged" in body
    assert "Untagged" not in body


def test_uncategorized_means_documents_in_no_folder(answers):
    answers(docs=[_Doc(id=1, name="Filed", collection_id=2),
                  _Doc(id=2, name="Loose", collection_id=None, _folder=None)])
    body = flat(_q(_reader(), folder="uncategorized").text)
    assert "Loose" in body
    assert "Filed" not in body


# ---------------------------------------------------------------------------
# The folder dimension needs a permission the page does not
# ---------------------------------------------------------------------------


@pytest.fixture
def folders(monkeypatch):
    def set(rows=None, raises=None):
        def listing(self):
            if raises is not None:
                raise raises
            return [type("C", (), {"id": i, "parent_id": p})()
                    for i, p in (rows or [])]

        monkeypatch.setattr(
            "ion.services.template_service.TemplateService.list_collections",
            listing)

    return set


def test_a_folder_filter_includes_subfolders(answers, folders):
    """`isInFolderOrSubfolder` walked this in the browser."""
    folders(rows=[(1, None), (2, 1), (3, 2)])
    answers(docs=[_Doc(id=10, name="Top", collection_id=1),
                  _Doc(id=11, name="Nested", collection_id=3),
                  _Doc(id=12, name="Elsewhere", collection_id=9)])
    body = flat(_q(_reader("template:read"), folder="1").text)
    assert "Top" in body
    assert "Nested" in body, "a grandchild folder is still in the subtree"
    assert "Elsewhere" not in body


def test_a_reader_without_template_read_is_told_the_folder_filter_is_withheld(
        answers, folders):
    """The page asked for the hierarchy, logged the refusal to the console
    and carried on, so the folder filter silently did nothing."""
    answers(docs=[_Doc(id=10, name="Top", collection_id=1)])
    resp = _q(_reader(), folder="1")
    body = flat(resp.text)
    assert "folder filter" in body.lower()
    assert "Top" in body, "the list still renders"
    assert resp.status_code == 200


def test_a_failed_hierarchy_read_says_so_rather_than_filtering_wrongly(
        answers, folders):
    folders(raises=RuntimeError("collections unreadable"))
    answers(docs=[_Doc(id=10, name="Top", collection_id=1)])
    body = flat(_q(_reader("template:read"), folder="1").text)
    assert "folder filter" in body.lower()
    assert "Top" in body


def test_no_folder_asked_for_reports_no_folder_state(answers):
    answers(docs=[_Doc()])
    body = _q(_reader()).json() if False else None
    with TestClient(_app(_reader())) as client:
        view = client.get(URL, headers={"accept": "application/json"}).json()
    assert view["folder_filter"] == "none"


def test_a_folder_that_is_not_a_number_is_a_failed_filter_not_an_empty_list(
        answers, folders):
    folders(rows=[(1, None)])
    answers(docs=[_Doc(id=10, name="Top", collection_id=1)])
    body = flat(_q(_reader("template:read"), folder="not-an-id").text)
    assert "Top" in body
    assert "folder filter" in body.lower()


# ---------------------------------------------------------------------------
# The sheet has to be reachable, not merely written
# ---------------------------------------------------------------------------


def test_the_page_links_its_stylesheet():
    """I wrote this sheet and did not link it, which is the same mistake
    that left the forensics playbook preview unstyled: the classes were in
    the markup, the rules were in a file, and nothing joined them. No route
    test can see it, because the fragment is correct either way."""
    page = PAGE.read_text(encoding="utf-8")
    assert "documents-page.css" in page
    head = re.search(r"\{%\s*block head_css\s*%\}(.*?)\{%\s*endblock\s*%\}",
                     page, re.S)
    assert head, "linked from head_css, not from the body"
    assert "documents-page.css" in head.group(1)


def test_nothing_that_outranks_the_sheet_claims_its_selectors():
    """head_css loses to ion-workspace.css and to ion-shell.css (the two
    blocks that used to sit in base.html's body) at equal specificity, so
    an overlap would mean a rule that is present and never wins."""
    workspace = (ROOT / "src/ion/web/static/css/ion-workspace.css").read_text(
        encoding="utf-8")
    shell = (ROOT / "src/ion/web/static/css/ion-shell.css").read_text(
        encoding="utf-8")
    base = (ROOT / "src/ion/web/templates/base.html").read_text(
        encoding="utf-8")
    for cls in ("doc-row", "doc-row-archived", "doc-unmeasured",
                "doc-filter-notice"):
        assert f".{cls}" not in workspace, cls
        assert f".{cls}" not in shell, cls
        assert f".{cls}" not in base, cls


def test_a_date_that_already_carries_an_offset_is_converted_not_relabelled(
        answers):
    """Caught by a mutation that dropped the astimezone and kept the "UTC"
    suffix, which would label a +02:00 timestamp as UTC without moving it.
    The same assertion exists for the cases timeline; it was missing here."""
    answers(docs=[_Doc(created_at="2026-09-01T12:30:00+02:00")])
    body = flat(_get(_reader()).text)
    assert "2026-09-01 10:30 UTC" in body
    assert "12:30" not in body
