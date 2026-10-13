"""The document version history as a fragment.

Measured on documents.html before the change, by reading loadVersions:

  * The Revert button was offered on every version that was not the current
    one. `POST /api/documents/{id}/revert/{n}` requires `document:update`,
    which `document:read` does not imply, so a reader got a button that
    answered 403. Same defect as the Delete control on the library list,
    and the same fix: ask the question the endpoint will ask.

  * ``data-args='[${v.version_number}]'`` interpolated into the attribute,
    so a payload whose version number was not a number produced JSON that
    event-delegation.js throws on, logs, and returns from. The control then
    looks live and does nothing.

  * `escapeHtml(v.amendment_reason || '-')` printed a dash for a version
    amended without a stated reason and the same dash for a payload that
    did not carry the key. An amendment nobody explained is a finding; a
    field we could not read is a different one.

  * `formatDate(v.created_at)`, which is `new Date(iso)` over `isoformat()`
    of a naive UTC column, so every date was the viewer's local reading of
    a UTC value.

  * `isCurrent` compared against `currentDocVersion`, a page variable set
    when the modal opened. The document's current version is a fact the
    server holds.
"""
from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui.documents import PERMISSION, REVERT, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/documents.html"

URL = "/ui/documents/5/versions"


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


def _reader(*extra):
    return _User(PERMISSION, *extra)


def _ver(n=2, **over):
    v = {"id": n, "version_number": n, "amendment_reason": "typo fixed",
         "amended_by": "lyndon", "created_at": "2026-09-01T10:30:00"}
    v.update(over)
    return type("V", (), v)()


@pytest.fixture
def answers(monkeypatch):
    def set(versions=None, raises=None, current=3, document=True):
        def get_by_id(self, document_id):
            if not document:
                return None
            return type("D", (), {"id": document_id,
                                  "current_version": current})()

        def list_versions(self, document_id):
            if raises is not None:
                raise raises
            return versions

        monkeypatch.setattr(
            "ion.storage.document_repository.DocumentRepository.get_by_id",
            get_by_id)
        monkeypatch.setattr(
            "ion.storage.document_repository.DocumentRepository.list_versions",
            list_versions)

    return set


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


# ---------------------------------------------------------------------------
# Gate and the three outcomes
# ---------------------------------------------------------------------------


def test_the_history_needs_the_pages_own_permission(answers):
    answers(versions=[])
    assert _get(_User()).status_code == 403
    assert _get(_reader()).status_code == 200


def test_a_read_that_raised_says_unavailable_not_empty(answers):
    answers(raises=RuntimeError("the repository fell over"))
    body = flat(_get(_reader()).text)
    assert "Version history unavailable" in body
    assert "No version history" not in body


def test_a_document_that_is_not_there_says_unavailable(answers):
    """The endpoint raises 404 for it, and a document we cannot read is not
    a document with no history."""
    answers(versions=[], document=False)
    body = flat(_get(_reader()).text)
    assert "Version history unavailable" in body
    assert "No version history" not in body


@pytest.mark.parametrize("versions", [None, "two", {}, 4])
def test_a_result_that_is_not_a_list_is_unreadable_not_empty(
        answers, versions):
    answers(versions=versions)
    body = flat(_get(_reader()).text)
    assert "Version history unavailable" in body, versions
    assert "No version history" not in body, versions


def test_no_history_says_so(answers):
    answers(versions=[])
    body = flat(_get(_reader()).text)
    assert "No version history available" in body
    assert "unavailable" not in body


def test_a_version_renders_its_number_reason_author_and_date(answers):
    answers(versions=[_ver(2)])
    body = flat(_get(_reader()).text)
    assert "v2" in body
    assert "typo fixed" in body
    assert "lyndon" in body
    assert "2026-09-01 10:30 UTC" in body


# ---------------------------------------------------------------------------
# Revert is a different permission
# ---------------------------------------------------------------------------


def test_a_reader_is_not_offered_revert(answers):
    """The defect. POST .../revert/{n} requires document:update, so every
    Revert click from a reader was a 403."""
    answers(versions=[_ver(2)], current=3)
    html = _get(_reader()).text
    assert "v2" in flat(html), "the row still renders"
    assert "confirmRevert" not in html


def test_an_editor_is_offered_revert(answers):
    answers(versions=[_ver(2)], current=3)
    assert "confirmRevert" in _get(_reader(REVERT)).text


def test_the_current_version_is_never_offered_revert(answers):
    answers(versions=[_ver(3)], current=3)
    html = _get(_reader(REVERT)).text
    assert "Current" in flat(html)
    assert "confirmRevert" not in html


def test_the_current_version_comes_from_the_server_not_the_page(answers):
    """`isCurrent` compared against a page variable set when the modal
    opened. The document row holds the fact."""
    answers(versions=[_ver(2), _ver(7)], current=7)
    body = flat(_get(_reader()).text)
    assert "v7 Current" in body
    assert "v2 Current" not in body


@pytest.mark.parametrize("current", [None, "latest", {}])
def test_an_unreadable_current_version_marks_nothing_current(
        answers, current):
    """Better than marking the wrong row: `=== currentDocVersion` against
    undefined matched nothing, which was right by accident."""
    answers(versions=[_ver(2)], current=current)
    body = flat(_get(_reader()).text)
    assert "v2" in body
    assert "Current" not in body


# ---------------------------------------------------------------------------
# The attribute, and the dash that meant two things
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("number", [2, "v2", None])
def test_every_data_args_is_parseable_json(answers, number):
    answers(versions=[_ver(number=number, version_number=number)],
            current=99)
    html = _get(_reader(REVERT)).text
    for raw in re.findall(r"data-args='([^']*)'", html):
        json.loads(unescape(raw))


def test_a_version_amended_without_a_reason_is_not_an_unreadable_one(
        answers):
    answers(versions=[_ver(2, amendment_reason=None)])
    body = flat(_get(_reader()).text)
    assert "no reason recorded" in body.lower()


def test_a_version_with_no_author_says_so(answers):
    answers(versions=[_ver(2, amended_by=None)])
    assert "unknown" in flat(_get(_reader()).text).lower()


@pytest.mark.parametrize("value", [None, "", "not a date"])
def test_an_unreadable_date_does_not_invent_one(answers, value):
    answers(versions=[_ver(2, created_at=value)])
    body = flat(_get(_reader()).text)
    assert "v2" in body
    assert "UTC" not in body


def test_an_entry_that_is_not_a_version_is_skipped_not_fatal(answers):
    answers(versions=["junk", _ver(2)])
    body = flat(_get(_reader()).text)
    assert "v2" in body
    assert "Version history unavailable" not in body


# ---------------------------------------------------------------------------
# CSP and the page
# ---------------------------------------------------------------------------


def test_the_fragment_has_no_inline_style_or_colour(answers):
    answers(versions=[_ver(2)])
    html = _get(_reader()).text
    assert "v2" in flat(html)
    assert not re.search(r'\sstyle="', html)
    assert "javascript:" not in html
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", html)


def test_the_route_answers_json_when_asked_for_json_only(answers):
    answers(versions=[_ver(2)], current=3)
    body = _get(_reader(), accept="application/json").json()
    assert body["rows"][0]["number"] == 2
    assert body["rows"][0]["is_current"] is False
    assert body["rows"][0]["may_revert"] is False


def test_the_page_no_longer_writes_the_version_table():
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    block = re.search(r"\bfunction loadVersions\(.*?\n\}", body, re.S)
    assert block, "the loader is still there"
    assert not re.search(r"\.innerHTML\s*=", block.group(0))
    assert "htmx.ajax" in block.group(0)
    assert "versions-table" not in block.group(0)
    assert "formatDate" not in block.group(0)


# ---------------------------------------------------------------------------
# The two modal headers
# ---------------------------------------------------------------------------


def _get_url(user, url):
    with TestClient(_app(user)) as client:
        return client.get(url)


def test_the_document_header_renders_its_badges(answers):
    answers(versions=[], current=4)
    body = flat(_get_url(_reader(), "/ui/documents/5/header").text)
    assert "v4" in body


def test_the_document_header_says_so_when_the_document_cannot_be_read(
        answers):
    """The modal opens on a click, so a failed read has to speak: the row
    otherwise keeps whatever the last document left in it."""
    answers(versions=[], document=False)
    body = flat(_get_url(_reader(), "/ui/documents/5/header").text)
    assert "could not be read" in body


@pytest.mark.parametrize("current", [None, "latest"])
def test_the_document_header_does_not_claim_v1(answers, current):
    """`doc.current_version || 1` printed a version it did not have."""
    answers(versions=[], current=current)
    body = flat(_get_url(_reader(), "/ui/documents/5/header").text)
    assert "v1" not in body
    assert "version unknown" in body


def test_the_version_header_renders_the_amendment(answers):
    answers(versions=[_ver(2)], current=3)
    body = flat(_get_url(_reader(), "/ui/documents/5/versions/2/header").text)
    assert "typo fixed" in body
    assert "lyndon" in body
    assert "2026-09-01 10:30 UTC" in body


def test_the_version_header_offers_revert_only_to_an_editor(answers):
    answers(versions=[_ver(2)], current=3)
    reader = _get_url(_reader(), "/ui/documents/5/versions/2/header").text
    editor = _get_url(_reader(REVERT),
                      "/ui/documents/5/versions/2/header").text
    assert "confirmRevert" not in reader
    assert "confirmRevert" in editor


def test_the_version_header_never_offers_revert_to_the_current_version(
        answers):
    answers(versions=[_ver(3)], current=3)
    html = _get_url(_reader(REVERT),
                    "/ui/documents/5/versions/3/header").text
    assert "Current" in flat(html)
    assert "confirmRevert" not in html


def test_a_version_that_is_not_there_says_so(answers):
    answers(versions=[_ver(2)], current=3)
    body = flat(_get_url(_reader(), "/ui/documents/5/versions/9/header").text)
    assert "could not be read" in body


def test_the_revert_button_is_swapped_into_the_footer_slot(answers):
    """It belongs in the modal footer, not in the meta row, so the fragment
    sends it there out of band. The shell carries the slot and no button."""
    answers(versions=[_ver(2)], current=3)
    html = _get_url(_reader(REVERT), "/ui/documents/5/versions/2/header").text
    assert 'hx-swap-oob="innerHTML:#revert-version-slot"' in html
    assert "confirmRevert" in html
    page = PAGE.read_text(encoding="utf-8")
    assert 'id="revert-version-slot"' in page
    assert "revert-version-btn" not in page, (
        "the shell's own button and its load-time listener are gone")


def test_a_reader_gets_an_empty_footer_slot_not_a_hidden_button(answers):
    """`style.display = 'none'` left the control in the DOM. A reader has no
    Revert button at all now, which is what the endpoint means."""
    answers(versions=[_ver(2)], current=3)
    html = _get_url(_reader(), "/ui/documents/5/versions/2/header").text
    assert 'id="revert-version-slot"' in html
    assert "confirmRevert" not in html
    assert "display" not in html
