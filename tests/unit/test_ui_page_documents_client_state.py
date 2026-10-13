"""What documents.html still does in the browser, and how.

Four of the page's write sites were a select being cleared and seeded with
its placeholder, `select.innerHTML = '<option value="">All Tags</option>'`,
with every real option built by createElement and appendChild just below.
An <option> is not markup a stylesheet sweep needs to reach, so the
redesign's reason for moving markup to the server does not apply: these
needed the DOM call that does the same thing without parsing a string, not
a fragment and a round trip.

The breadcrumb was the same kind of thing one step up: three elements, one
of which the page escaped by hand on one branch and not the other.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/documents.html"


def page() -> str:
    """The page with its Jinja comments stripped.

    Comments naming the thing being asserted have made four checks on this
    project pass against their own prose.
    """
    return re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)


def fn(name: str) -> str:
    body = page()
    match = re.search(rf"\bfunction {name}\(.*?\n\}}", body, re.S)
    assert match, f"{name} is still in the page"
    return match.group(0)


@pytest.mark.parametrize("name", [
    "updateFolderSelects", "updateParentSelect", "updateTagFilter",
])
def test_each_select_is_seeded_without_parsing_a_string(name):
    assert not re.search(r"\.innerHTML\s*=", fn(name)), name
    assert "seedSelect" in fn(name), name


def test_the_seed_helper_clears_before_it_adds():
    """Without the clear, every call appends another placeholder."""
    helper = fn("seedSelect")
    assert "replaceChildren()" in helper
    assert "createElement" in helper
    assert "textContent" in helper
    assert not re.search(r"\.innerHTML\s*=", helper)


def test_the_seed_helper_survives_a_missing_select():
    """Three of the four callers reach for a select inside a modal that may
    not be in the DOM yet. The page would have thrown on the assignment."""
    helper = fn("seedSelect")
    assert "if (!select) return null;" in helper
    for name in ("updateFolderSelects", "updateParentSelect",
                 "updateTagFilter"):
        assert "if (!seedSelect(" in fn(name), name


def test_the_breadcrumb_is_built_rather_than_parsed():
    body = fn("updateFolderPath")
    assert not re.search(r"\.innerHTML\s*=", body)
    assert "createElement" in body
    assert "textContent" in body
    assert "replaceChildren" in body


def test_the_breadcrumb_sets_its_action_as_attributes():
    """data-args has to survive JSON.parse, and setAttribute cannot produce
    a half-escaped attribute the way a template string could."""
    body = fn("updateFolderPath")
    assert "setAttribute('data-click-action', 'selectFolder')" in body
    assert "setAttribute('data-args', '[null]')" in body


def test_the_breadcrumb_does_not_print_the_word_undefined():
    """`${escapeHtml(folder.full_path)}` on a folder with no full_path
    printed the word."""
    body = fn("updateFolderPath")
    assert "full_path ?? " in body


def test_the_breadcrumb_clears_when_the_folder_is_gone():
    """The page left the previous crumb on screen when the selected folder
    was not in allCollections, so it named a folder you were not in."""
    body = fn("updateFolderPath")
    assert body.count("replaceChildren()") >= 2


def test_no_select_is_cleared_with_an_empty_string():
    """`select.innerHTML = ''` is the same defect in a different spelling,
    and it is what a later edit would reach for.

    A pin, not evidence. This already passed before the change, and it is
    the only one in this file that did: the other nine fail against the old
    page. It is here to stay true, not to show something was fixed.
    """
    body = page()
    assert not re.search(r"\.innerHTML\s*=\s*['\"]['\"]", body)
