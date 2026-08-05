"""Route audit phase 7f — `/translator` merged into `/tools`, plus diagnosable
fetch errors on `/integrations`.

**The merge.** `/translator` was a 277-line single-purpose page whose sibling tab
strip contained exactly one other entry: `/tools`, the 1076-line toolbox it
plainly belonged in. It is now the Translator tab there. Both sides were already
`alert:read`, so this is a pure relocation.

**The latent bug the merge exposed.** `switchToolTab()` ended with
`event.target.classList.add('active')` — the implicit global `window.event`.
That happens to work for a real click and is `undefined` for a programmatic call,
so the moment a deep link needed to select a tab, the panel would switch while
the button strip stayed on the old tab (or threw). Fixed by deriving the button
from the tab name.

**The `/integrations` error messages.** Nine loaders each did
`if (!response.ok) throw new Error('Failed to load X')`, collapsing session
expiry, permission denial, a 500 and a dropped connection into one identical
sentence — so a user reporting "it says failed to load" gave nobody anything to
go on. They now go through a helper that keeps the status code and the server's
`detail`, and names the two cases a user can act on (401 / 403).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ion.web.server import app

TEMPLATES = Path("src/ion/web/templates")


@pytest.fixture(scope="module")
def paths():
    return {r.path for r in app.routes}


@pytest.fixture(scope="module")
def tools() -> str:
    return (TEMPLATES / "tools.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def integrations() -> str:
    return (TEMPLATES / "integrations.html").read_text(encoding="utf-8")


def _script_block(html: str) -> str:
    m = re.search(r"\{%\s*block scripts\s*%\}(.*)", html, re.S)
    assert m, "template has no scripts block"
    return m.group(1)


def _strip_comments(js: str) -> str:
    """Assertions here are about executable code. A comment that *names* the
    banned pattern (explaining why it was removed) must not fail the test."""
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    return re.sub(r"^\s*//.*$", "", js, flags=re.M)


# ── route retirement ─────────────────────────────────────────────────────


def test_translator_route_still_served(paths):
    assert "/translator" in paths


def test_translator_template_is_gone():
    assert not (TEMPLATES / "translator.html").exists()


def test_translator_redirects_to_the_tools_tab():
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        resp = client.get("/translator", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/tools?tab=translator"


def test_translator_api_endpoints_untouched(paths):
    """`/alerts` and `/cases` call these directly and never went through the
    page — retiring the page must not disturb them."""
    for p in ("/api/translator/languages", "/api/translator/translate",
              "/api/translator/translate-file", "/api/translator/extract"):
        assert p in paths, p


# ── the merged tab ───────────────────────────────────────────────────────


def test_translator_is_a_tool_tab(tools):
    assert 'data-args=\'["translator"]\'' in tools
    assert 'id="tab-translator"' in tools


def test_ioc_stays_the_default_tab(tools):
    """Existing /tools users must land where they always did."""
    assert 'id="tab-ioc" class="tool-tab-content active"' in tools
    assert 'id="tab-translator" class="tool-tab-content"' in tools


def test_translator_markup_and_js_came_across(tools):
    for marker in ('id="t-source"', 'id="t-target"', 'id="t-input"',
                   'id="t-output"', 'id="t-translate-btn"'):
        assert marker in tools, marker
    js = _script_block(tools)
    for fn in ("loadLanguages", "translateText", "uploadAndTranslate", "updateSourceMeta"):
        assert re.search(rf"^(?:async )?function {fn}\b", js, re.M), fn


def test_dead_sibling_tab_strip_removed(tools):
    """The strip existed only to pair these two pages. With one page left it is
    a one-item nav — drop it rather than leave a stub."""
    assert "_nav_tabs.html" not in tools
    assert '"href": "/translator"' not in tools


# ── the latent `window.event` bug ────────────────────────────────────────


def test_switch_tool_tab_does_not_use_implicit_global_event(tools):
    js = _strip_comments(_script_block(tools))
    fn = js[js.index("function switchToolTab"):]
    fn = fn[:fn.index("\n}")]
    assert "event.target" not in fn, (
        "switchToolTab reads the implicit global `window.event`, which is "
        "undefined on a programmatic call — the deep link would leave the "
        "button strip out of sync with the visible panel"
    )
    # The active button must be derived from the tab name instead.
    assert "dataset.args" in fn or "data-args" in fn


def test_tools_deep_link_honoured(tools):
    js = _script_block(tools)
    assert "URLSearchParams" in js
    assert "switchToolTab(requested)" in js


def test_translator_init_deferred(tools):
    """A non-default tab must not fire /api/translator/languages on every
    /tools visit."""
    js = _script_block(tools)
    assert "window.ionInitTranslatorTab" in js
    # Anchor on the ASSIGNMENT, not the first mention — the call site inside
    # switchToolTab appears earlier in the file.
    init = js[js.index("window.ionInitTranslatorTab = function"):]
    init = init[:init.index("\n};")]
    assert "loadLanguages()" in init
    # ...and it must be idempotent — tab clicks are unbounded.
    assert "translatorInitialised" in init


def test_no_duplicate_top_level_declarations(tools):
    js = _script_block(tools)
    names = re.findall(r"^(?:const|let|var|function|async function)\s+(\w+)", js, re.M)
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, f"duplicated top-level declaration(s) after the merge: {dupes}"


# ── diagnosable errors on /integrations ──────────────────────────────────


def test_no_opaque_failed_to_load_throws_left(integrations):
    assert "throw new Error('Failed to load" not in integrations


def test_every_loader_goes_through_the_helper(integrations):
    js = _script_block(integrations)
    assert js.count("ionFetchJson(") >= 10  # 1 definition + 9 call sites


def test_helper_distinguishes_the_actionable_cases(integrations):
    js = _script_block(integrations)
    helper = js[js.index("async function ionFetchJson"):]
    helper = helper[:helper.index("\n}\n")]
    assert "401" in helper and "session has expired" in helper
    assert "403" in helper and "permission" in helper
    # A non-2xx must carry the status; a network drop must be distinguishable
    # from an HTTP error (fetch only rejects on the former).
    assert "response.status" in helper
    assert "Could not reach the server" in helper


def test_helper_surfaces_the_server_detail(integrations):
    """FastAPI puts the reason in `detail`; discarding it is what made this
    unreportable in the first place."""
    js = _script_block(integrations)
    helper = js[js.index("async function ionFetchJson"):]
    helper = helper[:helper.index("\n}\n")]
    assert "body.detail" in helper


# ── nav coherence ────────────────────────────────────────────────────────


def test_nav_no_longer_branches_on_translator():
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    assert "p.startswith('/translator')" not in base
