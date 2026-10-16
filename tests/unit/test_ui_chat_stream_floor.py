"""chat.html's write floor turned out to be zero.

This file said the page could not reach zero the way the rest of the
redesign does, because its centre is a token stream:

    contentEl.innerHTML = formatMessage(fullResponse);

runs once per chunk, and a server fragment per token would be a round
trip per token. That reasoning is right and it reached the wrong
conclusion. It argues against rendering each token on the server, not for
innerHTML: the markup does have to be built in the browser, but it does
not have to be assigned to a live element as a string.

`ionSetSafeHtml` in app.js parses with DOMParser, whose document is
inert, and gives the nodes to `replaceChildren`. One parse per token
either way, so the same work, and no write. The floor is zero and all
four sites are converted.

What the floor was protecting is still protected here: a stylesheet sweep
cannot reach markup built as a string, and every site still has to go
through the project's own sanitiser.

THE DOCGEN PREVIEW HAD ONE BRANCH THAT DID NOT

    if (format === 'markdown' && typeof marked !== 'undefined') {
        previewContent.innerHTML = safeMarkdown(docgenContent);
    } else if (format === 'html') {
        previewContent.innerHTML = docgenContent;
    } else {
        previewContent.innerHTML = '<pre>' + escapeHtml(docgenContent) + '</pre>';
    }

The markdown branch goes through DOMPurify and the plain branch escapes.
The html branch assigned model output straight to innerHTML. app.js says
what the rule is, right above the helper it bypassed:

    All user-controlled markdown MUST go through this function

The generated document is then offered for saving, so whether this is
self-XSS or stored XSS depends on how the documents page renders a saved
HTML document, which is a separate question from this one.

Everything else that was a write is static markup. Those are <template>
elements now, cloned rather than built from a string, which is what makes
a stylesheet sweep able to reach them at all.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/chat.html"
APP_JS = ROOT / "src/ion/web/static/js/app.js"


def _scripts() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", body,
                                   re.S))
    return re.sub(r"//[^\n]*", "", scripts)


def _writes() -> list[str]:
    """Every surviving runtime DOM write, as the status tool counts
    them."""
    return re.findall(r"[^\n]*(?:innerHTML\s*\+?=|insertAdjacentHTML"
                      r"|outerHTML\s*\+?=)[^\n]*", _scripts())


def _render_sites() -> list[str]:
    """The calls that replaced those writes."""
    return re.findall(r"ionSetSafeHtml\([^;]*\);", _scripts())


# ---------------------------------------------------------------------------
# The floor
# ---------------------------------------------------------------------------


def test_the_page_keeps_no_writes_at_all():
    """This asserted exactly four, as the floor. The floor was wrong, and
    the four sites are `ionSetSafeHtml` now."""
    writes = _writes()
    assert writes == [], writes


def test_the_four_render_sites_are_still_four():
    """The pair below would both pass on an empty page, since a loop over
    nothing asserts nothing. Counting the sites first is what stops that:
    if a render site disappeared, this fails rather than the checks
    quietly covering less.
    """
    assert len(_render_sites()) == 4, _render_sites()


def test_every_render_site_is_a_message_or_preview_body():
    for site in _render_sites():
        assert ("contentEl" in site or "previewContent" in site
                or "(body," in site), site


def test_every_render_site_goes_through_the_sanitiser():
    """safeMarkdown and safeHtml both route through DOMPurify, and
    formatMessage calls safeMarkdown or escapes first. The one branch that
    did neither assigned model output raw.

    ionSetSafeHtml does not sanitize, so losing the sanitiser on the way
    in would leave the markup inert and still hostile.
    """
    for site in _render_sites():
        assert ("formatMessage(" in site or "safeMarkdown(" in site
                or "safeHtml(" in site), site


def test_the_html_preview_branch_no_longer_assigns_raw_model_output():
    body = _scripts()
    assert not re.search(
        r"previewContent\.innerHTML\s*=\s*docgenContent\s*;", body)
    assert "safeHtml(docgenContent)" in body


def test_the_sanitiser_this_page_relies_on_still_exists():
    """A test that pins a helper by name is worth nothing if the helper
    is gone."""
    app = APP_JS.read_text(encoding="utf-8")
    assert "function safeHtml(" in app
    assert "function safeMarkdown(" in app
    assert "DOMPurify.sanitize" in app


def test_the_floor_is_documented_where_the_module_lives():
    """Comments wrap, so match on words rather than a phrase that a
    reflow can split."""
    module = (ROOT / "src/ion/web/ui/chat.py").read_text(encoding="utf-8")
    flat = " ".join(module.split())
    assert "token stream" in flat
    assert "round trip per token" in flat


# ---------------------------------------------------------------------------
# What stopped being a write
# ---------------------------------------------------------------------------


def test_the_static_markup_is_in_templates_rather_than_strings():
    page = PAGE.read_text(encoding="utf-8")
    for ident in ("tpl-ai-welcome", "tpl-ai-msg", "tpl-ai-generating",
                  "tpl-ai-generate-idle", "tpl-ai-cursor"):
        assert 'id="' + ident + '"' in page, ident
        assert "<template" in page


def test_the_message_shell_is_cloned_not_built():
    """Querying the clone for .ai-msg-avatar is fine. What must be gone
    is the markup: the avatar div written as a string."""
    body = _scripts()
    assert "tpl-ai-msg" in body
    assert "cloneNode" in body
    assert '<div class="ai-msg-avatar"' not in body
    assert '<div class="ai-msg ' not in body


def test_the_welcome_state_is_cloned_not_built():
    body = _scripts()
    assert "ai-welcome-orb" not in body
    assert "tpl-ai-welcome" in body


def test_the_two_button_states_are_cloned_not_built():
    body = _scripts()
    assert "Generating..." not in body
    assert "polygon points" not in body


def test_the_preview_error_is_set_as_text_not_markup():
    body = _scripts()
    assert "text-[var(--danger)] p-3" not in body
    assert "ai-preview-error" in body


def test_the_plain_format_preview_sets_text_on_a_pre_element():
    """`'<pre>' + escapeHtml(content)` was safe but it was still a write,
    and a <pre> built from a string is a <pre> no stylesheet sweep
    finds."""
    body = _scripts()
    assert "'<pre>'" not in body
    assert '"<pre>"' not in body
