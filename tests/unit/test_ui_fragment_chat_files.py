"""The AI chat file panel, the file viewer and the quick prompts.

`formatFileSize` reported a size for a file that had none:

    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';

Both comparisons are false for undefined, so the last line ran and the
file was listed as "NaN MB". A zero-byte file took the first branch and
read "0 B", which is right, so only the missing case was wrong, which is
the harder kind to notice.

`uploadedFiles = data.files || []` drew a payload in the wrong shape as
"No files attached".

The file id went raw into two attributes, one of them a single-quoted
data-args:

    <div class="ai-file-item" data-file-id="${f.id}">
    data-args='["${f.id}"]'

and the viewer did the same with `file.id` three more times.

The quick prompts came from AI_QUICK_PROMPTS, a JavaScript object in the
template, so the one list a reviewer would want to read sat in a script
block rather than anywhere the server could answer for.
"""
from __future__ import annotations

import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from ion.web.ui.chat import PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/chat.html"

FILES = "/ui/chat/files"
VIEWER = "/ui/chat/files/7"
PROMPTS = "/ui/chat/quick-prompts"


class _User:
    id = 1
    username = "chat-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _app(user):
    from ion.auth.dependencies import get_current_user

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    return application


def _get(url, user, **params):
    with TestClient(_app(user)) as client:
        return client.get(url, params=params)


def _reader():
    return _User(PERMISSION)


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


@pytest.fixture
def listing(monkeypatch):
    def set(payload=None, raises=None):
        async def handler(current_user=None):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr(
            "ion.web.ai_api.list_uploaded_files", handler)

    return set


@pytest.fixture
def one_file(monkeypatch):
    def set(payload=None, raises=None):
        async def handler(file_id, current_user=None):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr(
            "ion.web.ai_api.get_file_content", handler)

    return set


def _file(**over):
    f = {"id": 7, "name": "notes.txt", "size": 2048}
    f.update(over)
    return f


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def test_every_panel_needs_the_chat_permission(listing, one_file):
    listing(payload={"files": []})
    one_file(payload=_file(content="x"))
    for url in (FILES, VIEWER, PROMPTS):
        assert _get(url, _User()).status_code == 403, url
        assert _get(url, _reader()).status_code == 200, url


# ---------------------------------------------------------------------------
# The file list
# ---------------------------------------------------------------------------


def test_a_file_is_listed_with_its_name_and_size(listing):
    listing(payload={"files": [_file()]})
    body = flat(_get(FILES, _reader()).text)
    assert "notes.txt" in body
    assert "2.0 KB" in body


def test_a_file_with_no_size_is_not_reported_as_nan_megabytes(listing):
    """Both comparisons are false for undefined, so the megabyte branch
    ran and the file read "NaN MB"."""
    listing(payload={"files": [_file(size=None)]})
    html = _get(FILES, _reader()).text
    assert "NaN" not in html
    assert "notes.txt" in flat(html)
    assert "an-absent" in html


def test_a_zero_byte_file_is_reported_as_zero_bytes(listing):
    listing(payload={"files": [_file(size=0)]})
    assert "0 B" in flat(_get(FILES, _reader()).text)


@pytest.mark.parametrize("size,label", [
    (512, "512 B"), (1536, "1.5 KB"), (2097152, "2.0 MB"),
])
def test_the_size_thresholds_are_unchanged(listing, size, label):
    listing(payload={"files": [_file(size=size)]})
    assert label in flat(_get(FILES, _reader()).text)


def test_a_file_name_is_escaped(listing):
    listing(payload={"files": [_file(name="<script>alert(1)</script>")]})
    html = _get(FILES, _reader()).text
    assert "<script>alert(1)" not in html
    assert "alert(1)" in flat(html)


def test_a_file_id_is_serialised_rather_than_interpolated(listing):
    listing(payload={"files": [_file(id='" onclick="alert(1)')]})
    html = _get(FILES, _reader()).text
    assert 'onclick="alert(1)' not in html


def test_no_files_says_so(listing):
    listing(payload={"files": []})
    assert "No files attached" in flat(_get(FILES, _reader()).text)


def test_a_files_payload_that_is_not_a_list_is_not_no_files(listing):
    """`data.files || []` drew it as an empty attachment panel."""
    listing(payload={"files": "broken"})
    body = flat(_get(FILES, _reader()).text)
    assert "No files attached" not in body
    assert "not in a shape" in body or "could not" in body.lower()


def test_a_payload_of_none_is_a_failure_not_an_empty_panel(listing):
    """`for db in get_session(): return {...}` returns None if the
    generator yields nothing, and `data.files || []` made that an empty
    attachment panel."""
    listing(payload=None)
    body = flat(_get(FILES, _reader()).text)
    assert "No files attached" not in body
    assert "could not" in body.lower()


def test_a_failed_listing_is_reported(listing):
    """The page logged to the console and left the panel as it was, so a
    failed read looked like whatever was on screen before."""
    listing(raises=RuntimeError("the store went away"))
    body = flat(_get(FILES, _reader()).text).lower()
    assert "could not" in body
    assert "no files attached" not in body


def test_a_refusal_is_reported(listing):
    listing(raises=HTTPException(status_code=403, detail="not your file"))
    assert "not your file" in flat(_get(FILES, _reader()).text)


# ---------------------------------------------------------------------------
# The file viewer
# ---------------------------------------------------------------------------


def test_the_viewer_shows_the_content_once_in_each_place(one_file):
    """A <pre> to read and a textarea to edit, both escaped."""
    one_file(payload=_file(content="line one\nline two"))
    html = _get(VIEWER, _reader()).text
    assert html.count("line one") == 2
    assert "file-content-view" in html
    assert "file-content-edit" in html


def test_the_viewer_escapes_the_content(one_file):
    one_file(payload=_file(content="</textarea><script>alert(1)</script>"))
    html = _get(VIEWER, _reader()).text
    assert "</textarea><script>" not in html
    assert "<script>alert(1)" not in html


def test_a_file_with_no_content_says_so_rather_than_showing_undefined(
        one_file):
    one_file(payload=_file())
    html = _get(VIEWER, _reader()).text
    assert "undefined" not in html
    assert "no content" in flat(html).lower()


def test_the_viewer_reports_a_failed_read(one_file):
    """`showToast('Failed to load file')` was the only signal, and the
    modal never opened, so a transient failure and a file that is gone
    looked the same."""
    one_file(raises=RuntimeError("gone"))
    body = flat(_get(VIEWER, _reader()).text).lower()
    assert "could not" in body


def test_the_viewer_reports_a_refusal_with_its_reason(one_file):
    one_file(raises=HTTPException(status_code=404, detail="no such file"))
    assert "no such file" in flat(_get(VIEWER, _reader()).text)


# ---------------------------------------------------------------------------
# Quick prompts
# ---------------------------------------------------------------------------


def test_the_prompts_for_a_context_are_served(listing):
    html = _get(PROMPTS, _reader(), context="security").text
    assert "ai-qp" in html
    assert len(re.findall(r'class="ai-qp"', html)) >= 2


def test_an_unknown_context_serves_no_prompts_rather_than_failing():
    html = _get(PROMPTS, _reader(), context="not-a-context").text
    assert "ai-qp" not in html


def test_a_prompt_carries_its_text_as_a_value_not_as_its_label():
    """The page read the button's textContent back as the prompt, so any
    change to the label silently changed what was sent."""
    html = _get(PROMPTS, _reader(), context="security").text
    assert "data-prompt=" in html


def test_every_context_the_module_knows_has_prompts():
    from ion.web.ui.chat import QUICK_PROMPTS

    assert QUICK_PROMPTS
    for context, prompts in QUICK_PROMPTS.items():
        assert prompts, context
        assert all(isinstance(p, str) and p.strip() for p in prompts), context


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _page_js() -> str:
    """Only the script blocks, with comments stripped.

    A claim about the JavaScript has to be checked against the
    JavaScript: `ai-file-modal-content` and `ai-file-item` are still
    rules in the page's own style block, and prose has broken five checks
    on this project by matching the thing it describes.
    """
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", body,
                                   re.S))
    return re.sub(r"//[^\n]*", "", scripts)


def test_the_page_no_longer_builds_the_file_panels():
    """renderFiles survives as the htmx call, like every other converted
    panel. What must be gone is the markup and the size arithmetic."""
    body = _page_js()
    assert "function formatFileSize" not in body
    assert "ai-file-modal-content" not in body
    assert "ai-file-item" not in body
    render = re.search(r"function renderFiles\(\).*?\n    \}", body, re.S)
    assert render, "renderFiles"
    assert "htmx.ajax" in render.group(0)
    assert not re.search(r"\.innerHTML\s*\+?=", render.group(0))


def test_the_page_no_longer_carries_the_prompt_list():
    body = _page_js()
    assert "AI_QUICK_PROMPTS" not in body
