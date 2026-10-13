"""What chat.html is allowed to still write at runtime, and why.

The chat page cannot reach zero runtime writes the way the rest of the
redesign does. Its centre is a token stream:

    contentEl.innerHTML = formatMessage(fullResponse);

runs once per chunk, and a server fragment per token would be a round trip
per token. So three writes stay. This file pins which three, so the next
sweep of the stylesheet knows what it cannot reach, and checks that each
one goes through the project's own sanitiser.

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


# ---------------------------------------------------------------------------
# The floor
# ---------------------------------------------------------------------------


def test_the_page_keeps_exactly_the_streaming_writes():
    """Four: the message body as it is created and again on every chunk,
    and the docgen preview's two sanitising branches."""
    writes = _writes()
    assert len(writes) == 4, writes


def test_every_surviving_write_is_a_message_or_preview_body():
    for write in _writes():
        assert ("contentEl" in write or "previewContent" in write
                or "body.innerHTML" in write), write


def test_every_surviving_write_goes_through_the_sanitiser():
    """safeMarkdown and safeHtml both route through DOMPurify. The one
    branch that did neither assigned model output raw."""
    for write in _writes():
        assert ("formatMessage(" in write or "safeMarkdown(" in write
                or "safeHtml(" in write), write


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
