"""The two folder trees as fragments.

Measured on documents.html before the change:

  * Both trees were built from `allCollections`, the
    `/api/collections?flat=true` read. That endpoint requires
    `template:read` and this page is gated on `document:read`, so an
    account can be entitled to the documents and not to the folders they
    sit in. loadCollections logged the refusal to the console and carried
    on, so such an account got an empty sidebar, no folder badges, and
    nothing saying why.

  * The manage tree's Delete button was offered to every reader. DELETE
    /api/collections/{id} requires `template:delete`.

  * ``data-args='[${f.id}, ${JSON.stringify(f.name)}]'``. The same defect
    as the document list's Delete control: JSON.stringify escapes " and not
    ', the attribute is single quoted, so a folder called "Bob's folder"
    closed it early and the control silently did nothing.

  * `(f.document_count || 0)`. The API builds that count as
    `len(c.documents) if hasattr(c, 'documents') else 0`, so a schema that
    cannot count documents reported every folder as holding none.
"""
from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui.documents import (
    FOLDER_DELETE,
    FOLDER_PERMISSION,
    PERMISSION,
    router,
)

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/documents.html"
MANAGE = "/ui/documents/folders/manage"


class _User:
    username = "docs-tester"

    def __init__(self, *permissions):
        self.id = 1
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


def _get(user, url="/ui/documents/folders"):
    with TestClient(_app(user)) as client:
        return client.get(url)


def _reader(*extra):
    return _User(PERMISSION, *extra)


class _Col:
    def __init__(self, ident, name, parent=None, children=(), docs=0,
                 templates=0, path=None, countable=True):
        self.id = ident
        self.name = name
        self.parent_id = parent
        self.children = list(children)
        self.full_path = path or name
        self.templates = [object()] * templates
        if countable:
            self.documents = [object()] * docs


@pytest.fixture
def folders(monkeypatch):
    def set(rows=None, raises=None):
        def listing(self):
            if raises is not None:
                raise raises
            return rows

        monkeypatch.setattr(
            "ion.services.template_service.TemplateService.list_collections",
            listing)

    return set


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


# ---------------------------------------------------------------------------
# Four states, not three
# ---------------------------------------------------------------------------


def test_a_reader_without_template_read_is_told_rather_than_shown_nothing(
        folders):
    """The defect. An empty sidebar and no reason for it."""
    folders(rows=[_Col(1, "Runbooks")])
    body = flat(_get(_reader()).text)
    assert "does not have" in body
    assert "Runbooks" not in body


def test_a_failed_hierarchy_read_says_so_rather_than_empty(folders):
    folders(raises=RuntimeError("collections unreadable"))
    body = flat(_get(_reader(FOLDER_PERMISSION)).text)
    assert "did not answer" in body
    assert "No folders yet" not in body


@pytest.mark.parametrize("rows", [None, "two", {}])
def test_a_result_that_is_not_a_list_is_a_failure(folders, rows):
    folders(rows=rows)
    assert "did not answer" in flat(_get(_reader(FOLDER_PERMISSION)).text)


def test_no_folders_says_so(folders):
    folders(rows=[])
    body = flat(_get(_reader(FOLDER_PERMISSION)).text)
    assert "No folders yet" in body
    assert "did not answer" not in body


def test_the_tree_renders_its_folders_and_nests_them(folders):
    child = _Col(2, "Nested", parent=1)
    folders(rows=[_Col(1, "Runbooks", children=[child]), child])
    html = _get(_reader(FOLDER_PERMISSION)).text
    body = flat(html)
    assert "Runbooks" in body
    assert "Nested" in body
    assert "folder-children" in html, "the child is indented"
    assert "icon-folder-open" in html, "a parent shows an open folder"


def test_only_root_folders_are_drawn_at_the_top_level(folders):
    """A flat list contains the children too, and drawing them at the root
    as well would show every nested folder twice."""
    child = _Col(2, "Nested", parent=1)
    folders(rows=[_Col(1, "Runbooks", children=[child]), child])
    assert flat(_get(_reader(FOLDER_PERMISSION)).text).count("Nested") == 1


def test_the_selected_folder_is_marked_from_the_query(folders):
    """`selectedFolderId === f.id` was page state; the fragment is told."""
    folders(rows=[_Col(1, "Runbooks"), _Col(2, "Other")])
    html = _get(_reader(FOLDER_PERMISSION),
                "/ui/documents/folders?selected=2").text
    marked = re.findall(r'class="folder-item active" data-id="(\d+)"', html)
    assert marked == ["2"], html


@pytest.mark.parametrize("selected", ["", "uncategorized", "not-an-id"])
def test_no_usable_selection_marks_nothing_active(folders, selected):
    folders(rows=[_Col(1, "Runbooks")])
    html = _get(_reader(FOLDER_PERMISSION),
                "/ui/documents/folders?selected=" + selected).text
    assert "folder-item active" not in html


# ---------------------------------------------------------------------------
# Counts
# ---------------------------------------------------------------------------


def test_a_folder_reports_its_document_count(folders):
    folders(rows=[_Col(1, "Runbooks", docs=3)])
    assert "(3)" in flat(_get(_reader(FOLDER_PERMISSION)).text)


def test_a_schema_that_cannot_count_documents_says_nothing_not_zero(folders):
    """`len(c.documents) if hasattr(c, 'documents') else 0` reported every
    folder as holding none."""
    folders(rows=[_Col(1, "Runbooks", countable=False)])
    body = flat(_get(_reader(FOLDER_PERMISSION)).text)
    assert "Runbooks" in body
    assert "(0)" not in body


# ---------------------------------------------------------------------------
# The manage tree, where Delete lives
# ---------------------------------------------------------------------------


def test_a_reader_is_not_offered_delete(folders):
    folders(rows=[_Col(1, "Runbooks")])
    html = _get(_reader(FOLDER_PERMISSION), MANAGE).text
    assert "Runbooks" in flat(html)
    assert "deleteFolder" not in html


def test_a_holder_of_template_delete_is_offered_delete(folders):
    folders(rows=[_Col(1, "Runbooks")])
    assert "deleteFolder" in _get(
        _reader(FOLDER_PERMISSION, FOLDER_DELETE), MANAGE).text


@pytest.mark.parametrize("name", ["Bob's folder", 'The "quoted" folder'])
def test_a_folder_name_with_punctuation_still_yields_parseable_args(
        folders, name):
    folders(rows=[_Col(1, name)])
    html = _get(_reader(FOLDER_PERMISSION, FOLDER_DELETE), MANAGE).text
    found = re.findall(r"data-args='([^']*)'", html)
    assert found, name
    for raw in found:
        json.loads(unescape(raw))


def test_the_manage_tree_reports_both_counts(folders):
    folders(rows=[_Col(1, "Runbooks", docs=2, templates=5)])
    body = flat(_get(_reader(FOLDER_PERMISSION), MANAGE).text)
    assert "5 templates" in body
    assert "2 docs" in body


# ---------------------------------------------------------------------------
# CSP and the page
# ---------------------------------------------------------------------------


def test_neither_tree_ships_colour_or_inline_style(folders):
    folders(rows=[_Col(1, "Runbooks")])
    for url in ("/ui/documents/folders", MANAGE):
        html = _get(_reader(FOLDER_PERMISSION, FOLDER_DELETE), url).text
        assert "Runbooks" in flat(html), url
        assert not re.search(r'\sstyle="', html), url
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b", html), url


def test_the_page_no_longer_builds_either_tree():
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    for name in ("renderFolderTree", "renderFoldersManageTree"):
        block = re.search(r"\bfunction " + name + r"\(.*?\n\}", body, re.S)
        assert block, name
        assert not re.search(r"\.innerHTML\s*=", block.group(0)), name
        assert "htmx.ajax" in block.group(0), name
    for gone in ("renderFolderItems", "renderFolderManageItems"):
        assert "function " + gone not in body, gone
