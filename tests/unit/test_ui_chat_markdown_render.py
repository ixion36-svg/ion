"""chat.html renders model output through nodes rather than innerHTML.

Four assignments were left on this page, and all four were the same
thing: a sanitized HTML string put into a live element with
`innerHTML =`. They are the last of the class `ui/template_render.py`
records as unavoidable on the client, because ION has no server-side HTML
sanitiser in its dependencies, so markdown from a model cannot be
rendered by a Jinja template.

Unavoidable on the client is not the same as unavoidable through
innerHTML. `DOMParser.parseFromString` produces an inert document: its
scripts never run and its `img` and `iframe` never fetch, so a payload
that survived DOMPurify has no live element to act on while the markup is
being read. `replaceChildren` then adopts the parsed nodes. cases.html
and template_render.html already do exactly this, so this is the repo's
own pattern rather than a new one.

WHY NOT SANITISE STRAIGHT TO A FRAGMENT

DOMPurify's `RETURN_DOM_FRAGMENT` would do it in one step, which is what
`renderCaseMarkdown` uses. It is wrong here. `formatMessage` has a
fallback for when `marked` is absent: it escapes the content first and
then adds `pre`, `code`, `strong` and `br` itself. That markup is the
page's, not the model's, and routing it through a helper that degrades to
a text node when DOMPurify is missing would have shown an analyst the
literal tags. Parsing a string that is already either sanitized or
escaped keeps all four library-availability combinations behaving as they
did.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/chat.html"
APP_JS = ROOT / "src/ion/web/static/js/app.js"


def _scripts() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"), flags=re.S)
    scripts = "\n".join(
        re.findall(r"<script[^>]*>(.*?)</script>", body, re.S))
    return re.sub(r"//[^\n]*", "", scripts)


# ---------------------------------------------------------------------------
# The helper
# ---------------------------------------------------------------------------


def test_the_helper_exists_and_parses_inertly():
    source = APP_JS.read_text(encoding="utf-8")
    helper = re.search(r"function ionSetSafeHtml\(.*?\n\}", source, re.S)
    assert helper, "ionSetSafeHtml"
    body = helper.group(0)
    assert "DOMParser" in body
    assert "replaceChildren" in body
    assert "innerHTML" not in body


def test_the_helper_does_not_sanitise_and_so_says_so():
    """It takes markup the caller has already put through `safeHtml` or
    `safeMarkdown`. A helper that looked like it sanitised and did not
    would be worse than no helper, so the contract is in the docstring
    above it and this asserts the docstring is there."""
    source = APP_JS.read_text(encoding="utf-8")
    before = source[:source.index("function ionSetSafeHtml(")]
    doc = before[before.rindex("/**"):]
    assert "already" in doc.lower()
    assert "safeMarkdown" in doc or "safeHtml" in doc


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def test_the_page_writes_no_markup_at_runtime():
    """The measured column. All four sites, not three."""
    writes = re.findall(
        r"[^\n]*(?:innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=)[^\n]*",
        _scripts())
    assert writes == [], writes


def test_every_render_still_goes_through_a_sanitiser():
    """The point of the conversion is the sink, not the sanitising. If a
    call site lost its `safeMarkdown` or `safeHtml` on the way, the markup
    would be inert and still hostile."""
    body = _scripts()
    for call in re.findall(r"ionSetSafeHtml\(([^;]*)\);", body):
        assert ("formatMessage" in call or "safeMarkdown" in call
                or "safeHtml" in call), call


def test_all_four_sites_converted():
    body = _scripts()
    assert len(re.findall(r"ionSetSafeHtml\(", body)) == 4


def test_the_html_preview_branch_still_sanitises():
    """This branch assigned model output straight to innerHTML before, and
    the comment that recorded it is the reason to keep asserting it."""
    body = _scripts()
    assert "safeHtml(docgenContent)" in body


def test_the_marked_fallback_markup_is_untouched():
    """`formatMessage` adds this markup itself around escaped content. It
    must keep doing so, because the escape happens first and the helper
    does not sanitise."""
    body = _scripts()
    formatter = re.search(r"function formatMessage\(.*?\n    \}", body, re.S)
    assert formatter, "formatMessage"
    source = formatter.group(0)
    assert "escapeHtml(content)" in source
    assert "<pre><code" in source
