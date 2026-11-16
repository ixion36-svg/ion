"""The toolbox's client-state renders.

Fourteen of /tools' nineteen innerHTML writes hold no server-side answer.
Defanging pasted text, counting detected IOCs, converting a timestamp,
identifying a hash, parsing a URL, testing a regex, reading email headers
and parsing a log line all operate on text the analyst typed into the
browser. There is no read to make and inventing a /ui route for one would
post that text to ION to be handed straight back, so the markup moved into
<template> elements in _fragments/tools_client.html and the page's script
clones one and sets textContent.

The five writes that did read something ION holds became fragments, and
ion/web/ui/tools.py and its own test file cover those.

What is left to test here is the structure the technique depends on. Five
things break it silently:

  A <template> inside a <script> is inert text, so cloneTemplate finds no
  content and returns null, and the caller's `if (!x) return` makes the
  control vanish rather than fail.

  A cloneTemplate id with no matching element does the same.

  A duplicate template id resolves to whichever comes first in the
  document, so one caller silently renders the other's markup.

  A data-args built by string interpolation parses as invalid JSON in
  event-delegation.js, which logs and returns. The control looks live and
  does nothing. Every Lookup button beside a detected IOC was built that
  way on this page, with the IOC itself interpolated through escapeHtml,
  which turns a double quote into &quot; and the browser turns that back
  into a quote inside the JSON string.

  A class the script toggles that no stylesheet paints. The detected-IOC
  panel hid behind `hidden` and toggled `style.display`, which took two
  clicks to open; it toggles the class now, so the class has to be one
  that paints.

WHAT WAS SHOWN TO FAIL

Run against the page as it stood, with tools_client.html removed, 23 of
the 24 assertions here fail: there were no templates at all, nineteen DOM
writes, and `data-args='["${escapeHtml(m)}"]'` in the script.

The one that passes is the painted-class check, and it is a pin rather
than evidence: the old page toggled only `active` and `hidden`, which are
both painted. It is kept because this conversion changed which class the
details panel toggles, and that is exactly the edit that strands a class
nothing paints.
"""
from __future__ import annotations

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/tools.html"
CLIENT = ROOT / "src/ion/web/templates/_fragments/tools_client.html"

SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>", re.S | re.I)
JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.S)
HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
TEMPLATE_ID = re.compile(r"<template\s+id=\"([^\"]+)\"")
CLONE = re.compile(r"cloneTemplate\(\s*'([^']+)'\s*\)|tplText\(\s*'([^']+)'")
WRITES = re.compile(r"innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=")
TOGGLED = re.compile(r"""classList\.(?:add|toggle)\(\s*['"]([^'"]+)['"]""")


def _blank(m: re.Match) -> str:
    """Replace a region with as many newlines as it held, so a reported
    line number still points at the real file."""
    return "\n" * m.group(0).count("\n")


def page() -> str:
    """The page with its comments blanked.

    Four separate checks in this project have passed against their own
    explanatory prose, and this page's comments now name the defects each
    test below is about, so the comments have to go before any substring
    match is meaningful.
    """
    text = PAGE.read_text(encoding="utf-8").replace("\r\n", "\n")
    return HTML_COMMENT.sub(_blank, JINJA_COMMENT.sub(_blank, text))


def client() -> str:
    text = CLIENT.read_text(encoding="utf-8").replace("\r\n", "\n")
    return JINJA_COMMENT.sub(_blank, text)


def markup() -> str:
    """Every element of the page, its script bodies blanked.

    Without this a template id named in a JS comment reads as a defined
    template.
    """
    shell = SCRIPT.sub(
        lambda m: "<script>" + "\n" * m.group(1).count("\n") + "</script>",
        page(),
    )
    return shell + "\n" + client()


def scripts() -> str:
    """Every script body on the page, comments removed.

    A template id named in a comment would otherwise read as a cloned id,
    and this page's comments name several.
    """
    return _strip_js_comments("\n".join(SCRIPT.findall(page())))


def cloned() -> set[str]:
    return {g for m in CLONE.finditer(scripts()) for g in m.groups() if g}


def _end_of_function(text: str, start: int) -> int:
    """The offset just past the closing brace of the function at `start`.

    Brace depth alone is not enough on this page. parseLog contains
    `input.startsWith('{')`, a lone brace inside a string literal, and a
    naive counter never comes back to depth zero: three tests here reported
    "unbalanced braces in parseLog" against perfectly balanced code. So
    this skips string literals, template literals and comments while it
    counts.
    """
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch in "'\"`":
            quote = ch
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == quote:
                    break
                i += 1
        elif text.startswith("//", i):
            i = text.find("\n", i)
            if i == -1:
                break
        elif text.startswith("/*", i):
            end = text.find("*/", i)
            i = len(text) if end == -1 else end + 1
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise AssertionError("unbalanced braces from offset %d" % start)


def _strip_js_comments(body: str) -> str:
    """Drop whole-line JS comments.

    Four separate checks in this project have passed against their own
    explanatory prose, and one here failed the other way round: this page's
    comments now name the defect each test is about, so
    `assert "style.display" not in fn("toggleIocDetails")` matched the
    sentence explaining why style.display is gone.
    """
    kept = []
    for line in body.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("*") \
                or stripped.startswith("/*"):
            continue
        kept.append(line)
    return "\n".join(kept)


def fn(name: str) -> str:
    """One function's body, comments removed."""
    text = page()
    m = re.search(r"^[ \t]*(?:async\s+)?function\s+" + re.escape(name) + r"\s*\(",
                  text, re.M)
    assert m, f"no function {name}"
    return _strip_js_comments(text[m.start():_end_of_function(text, m.start())])


def tpl(tid: str) -> str:
    """One <template> element's inner markup."""
    text = markup()
    start = text.index(f'<template id="{tid}"')
    return text[start:text.index("</template>", start)]


def painted() -> set[str]:
    names: set[str] = set()
    css_in = re.compile(r"\.(-?[_a-zA-Z][\w-]*)")
    for f in sorted((ROOT / "src/ion/web/static/css").glob("*.css")):
        names |= set(css_in.findall(f.read_text(encoding="utf-8", errors="replace")))
    return names


# ---------------------------------------------------------------------------
# The measure, and the ways the technique fails without a sound
# ---------------------------------------------------------------------------


def test_the_page_makes_no_runtime_dom_write_anywhere():
    """The point of the conversion, counted over the whole file rather than
    per function so a new writer anywhere trips it.
    tools/ui_redesign_status.py measures the same thing and is the only
    thing that decides whether the page is done."""
    assert WRITES.findall(page()) == []
    assert WRITES.findall(client()) == []


def test_the_client_templates_are_included_outside_the_script_block():
    """A <template> inside a <script> is text, not an element.
    document.getElementById finds nothing, cloneTemplate returns null, and
    every control built from it quietly does not appear."""
    body = page()
    include = body.index('{% include "_fragments/tools_client.html" %}')
    for m in SCRIPT.finditer(body):
        assert not (m.start() < include < m.end()), "the include is inside a script"
    for script_body in SCRIPT.findall(body):
        assert TEMPLATE_ID.findall(script_body) == []


def test_every_cloned_id_is_a_template_that_exists():
    defined = set(TEMPLATE_ID.findall(markup()))
    assert defined, "no templates found; the anchor has moved"
    assert cloned() - defined == set()
    assert defined - cloned() == set(), "a template nothing clones is dead markup"


def test_no_template_id_is_defined_twice():
    """Two elements with one id resolve to whichever is first in document
    order, so the second caller silently renders the first's markup."""
    ids = TEMPLATE_ID.findall(markup())
    assert {i for i in ids if ids.count(i) > 1} == set()


def test_no_data_args_is_built_by_string_interpolation():
    """The dispatcher parses data-args with JSON.parse and on a throw it
    logs and returns. Every Lookup button beside a detected IOC was built
    as `data-args='["${escapeHtml(m)}"]'`, and escapeHtml turns a double
    quote into &quot; which the browser decodes to a bare quote inside the
    JSON string, so an IOC containing one made the button dead."""
    for body in SCRIPT.findall(page()):
        assert not re.search(r"data-args=[\"'][^\"']*\$\{", body)
    assigns = re.findall(r"\.dataset\.args\s*=\s*(.+)", scripts())
    assert assigns, "nothing assigns data-args; the anchor has moved"
    for value in assigns:
        assert value.lstrip().startswith("JSON.stringify"), value


def test_every_literal_data_args_in_the_markup_is_valid_json():
    """The shell's own data-args are hand-written, so they are parsed
    rather than assumed."""
    found = re.findall(r"data-args='([^']*)'", markup())
    assert found, "no literal data-args found; the anchor has moved"
    for raw in found:
        assert isinstance(json.loads(raw), list), raw


def test_no_markup_on_this_page_carries_an_inline_style_attribute():
    """style-src-attr is 'none', so an inline style= paints nothing at all
    and the element silently keeps the stylesheet's value."""
    assert not re.search(r"<[^>]*\sstyle=", markup())


def test_every_class_the_script_toggles_is_painted_somewhere():
    """A class the code applies that nothing paints is a control wired
    correctly and doing nothing visible. Checked here as well as repo-wide
    because this page's one state class changed in this conversion."""
    names = painted()
    assert len(names) > 1000, f"only {len(names)} classes found in selectors"
    for cls in TOGGLED.findall(scripts()):
        assert cls in names, cls


# ---------------------------------------------------------------------------
# The detected-IOC panel
# ---------------------------------------------------------------------------


def test_the_detected_ioc_counts_are_textcontent_and_the_list_is_cloned():
    body = fn("updateIOCStats")
    assert not WRITES.search(body)
    assert "cloneTemplate('tools-ioc-section')" in body
    assert "cloneTemplate('tools-ioc-item')" in body
    assert "cloneTemplate('tools-ioc-empty')" in body
    assert "[data-value]').textContent = match" in body


def test_a_detected_ioc_carries_its_value_to_the_dispatcher_as_json():
    assert "dataset.args = JSON.stringify([match])" in fn("updateIOCStats")
    assert 'data-click-action="lookupFromList"' in tpl("tools-ioc-item")


def test_the_details_panel_opens_on_the_first_click():
    """It took two. The panel was hidden by the `hidden` class and the
    toggle read `details.style.display === 'none'`, which on an empty
    inline value is false, so the first click set display:none on
    something already hidden and flipped the label the wrong way."""
    body = fn("toggleIocDetails")
    assert not WRITES.search(body)
    assert "classList.toggle('hidden')" in body
    assert "style.display" not in body
    assert "hidden ? 'Show Details' : 'Hide Details'" in body


# ---------------------------------------------------------------------------
# The custom find/replace rules
# ---------------------------------------------------------------------------


def test_a_rule_row_is_a_clone_and_its_fields_are_values_not_markup():
    body = fn("renderRules")
    assert not WRITES.search(body)
    assert "cloneTemplate('tools-rule-item')" in body
    assert "cloneTemplate('tools-rules-empty')" in body
    assert "find.value = rule.find == null ? '' : String(rule.find)" in body


def test_each_control_on_a_rule_row_carries_its_own_index_as_json():
    """Four controls, three different argument lists. The string version
    interpolated the index and the field name into the attribute, so a rule
    whose text held a double quote made the whole row dead."""
    body = fn("renderRules")
    assert "box.dataset.args = JSON.stringify([i])" in body
    assert "find.dataset.args = JSON.stringify([i, 'find', '$value'])" in body
    assert "replace.dataset.args = JSON.stringify([i, 'replace', '$value'])" in body


# ---------------------------------------------------------------------------
# The tables
# ---------------------------------------------------------------------------


def test_the_seven_tables_are_built_from_one_template():
    """Seven renders on this page were a table of label/value pairs built
    from seven separate string literals that had drifted: three emitted a
    <th> header row and four did not."""
    assert tpl("tools-table").count("<table") == 1
    body = fn("buildTable")
    assert not WRITES.search(body)
    for name in ("identifyHashes", "parseUrl", "testRegex",
                 "parseEmailHeaders", "parseLog"):
        assert "buildTable(" in fn(name), name
        assert not WRITES.search(fn(name)), name


def test_a_hash_is_shown_whole_rather_than_truncated():
    """`hash.substring(0, 40) + '...'` made two different SHA-256 digests
    sharing a prefix render identically, in a table whose only job is
    telling hashes apart."""
    body = fn("identifyHashes")
    assert "substring(0, 40)" not in body
    assert "{ text: hash, kind: 'code' }" in body


def test_an_unparseable_url_is_told_apart_from_an_empty_one():
    body = fn("parseUrl")
    assert not WRITES.search(body)
    assert "showError('url-results'" in body
    assert "replaceChildren()" in body


def test_an_unmatched_capture_group_is_not_reported_as_an_empty_one():
    """`g || '(empty)'` said the same thing for a group that matched the
    empty string and a group that did not participate in the match."""
    assert "'(unmatched)'" in fn("testRegex")


def test_the_regex_highlight_puts_the_analysts_text_in_text_nodes():
    """The one place on this page where the analyst's own text was wrapped
    in markup. Each segment is a text node and each match is a <mark>
    clone, so nothing is ever parsed."""
    body = fn("testRegex")
    assert not WRITES.search(body)
    assert "createTextNode(test.slice(lastIndex, hit.index))" in body
    assert "tplText('tools-mark', hit[0])" in body


def test_an_absent_authentication_result_is_said_rather_than_omitted():
    """The string version appended nothing when no SPF, DKIM or ARC header
    was present, so a message with no authentication result looked the same
    as one whose section the reader had not scrolled to."""
    body = fn("parseEmailHeaders")
    assert "No SPF, DKIM or ARC result in these headers." in body
    assert "No Received header in this paste." in body


def test_a_log_entry_no_format_matched_is_not_silence():
    """`if (parsed)` with nothing in the else, so an auto-detect that
    matched no format left the previous entry's table on screen."""
    body = fn("parseLog")
    assert not WRITES.search(body)
    assert "No known log format matched this entry." in body


def test_the_cef_header_version_is_not_overwritten_by_the_product_version():
    """The object literal had `version` twice, so parts[0] was replaced by
    parts[3] and the CEF format version was never shown."""
    body = fn("parseCEF")
    assert "cef_version: parts[0]" in body
    assert "product_version: parts[3]" in body


# ---------------------------------------------------------------------------
# The translator pane
# ---------------------------------------------------------------------------


def test_the_translation_placeholder_is_a_template_not_a_string():
    body = fn("setOutput")
    assert not WRITES.search(body)
    assert "cloneTemplate('tools-translation-placeholder')" in body


def test_translating_before_the_pickers_load_says_so_rather_than_posting():
    """The selects are rendered by /ui/tools/translator-languages, so
    before that fragment lands there is nothing to read. Reading `.value`
    off a missing element throws, and off an empty select gives '', which
    the API answers with a 400."""
    assert "el ? el.value : null" in fn("translatorLanguage")
    for name in ("translateText", "uploadAndTranslate"):
        assert "The language list has not loaded yet." in fn(name), name


def test_the_language_pickers_are_requested_once_on_first_activation():
    """As a standalone page the translator bootstrapped on parse. Keeping
    that would fire a round trip on every /tools visit for a tab nobody
    opened."""
    shell = markup()
    assert 'hx-get="/ui/tools/translator-languages"' in shell
    assert 'hx-trigger="ionTranslatorInit from:body"' in shell
    assert "htmx.trigger(document.body, 'ionTranslatorInit')" in scripts()
    assert "if (translatorInitialised) return;" in scripts()
