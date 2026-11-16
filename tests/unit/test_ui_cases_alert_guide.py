"""The alert guide's three sections and the rail's failure message.

These are the last two runtime writes `cases.html` owns itself, and both
are static structure, so they are templates rather than fragments. There
is nothing to fetch: `_appendCaseOnlySections` runs after the shared
alert-detail component mounts, on an alert object the page already holds.

A RULE NAME WITH A DOUBLE QUOTE BROKE THE PIN BUTTON

    data-args='[' + caseId + ',"' + esc(alertId) + '","'
            + esc(pinTitle) + '","' + esc(pinSev) + '"]'

`esc` turns a double quote into `&quot;`, which is correct for an
attribute and wrong for JSON inside one: the parser decodes it back and
the array ends early, so the button's arguments are truncated. The
playbook Start button had the identical bug.

Setting `dataset.args` from `JSON.stringify` avoids the question
entirely, because a DOM property assignment stores the value literally
and no HTML escaping stands between the two.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/cases.html"


def _scripts() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", body,
                                   re.S))
    return re.sub(r"//[^\n]*", "", scripts)


# ---------------------------------------------------------------------------
# The templates
# ---------------------------------------------------------------------------


def test_the_guide_sections_are_a_template():
    page = PAGE.read_text(encoding="utf-8")
    assert 'id="tpl-alert-guide"' in page
    assert "<template" in page
    for piece in ("cpanel-guide-sec", "cpanel-rule-guide-box",
                  "cpanel-proc-tree", "cpanel-pin-btn",
                  "Investigation guide", "Process tree",
                  "Pin as evidence"):
        assert piece in page, piece


def test_the_rail_failure_message_is_a_template():
    page = PAGE.read_text(encoding="utf-8")
    assert 'id="tpl-alert-detail-failed"' in page
    assert "Alert detail component failed to load" in page


def test_neither_is_built_from_a_string_any_more():
    body = _scripts()
    assert "cpanel-guide-title" not in body
    assert "Alert detail component failed to load" not in body


def test_the_loading_wording_is_a_label_not_markup():
    """"Loading rule guide" is still in the page's JavaScript, and should
    be. It is the third argument to `ionLoadFragment`, which hands it to
    `ionMessage`, which clones `ion-fragment-loading-template` and sets
    `textContent`. That is a label, not a structure.

    This test used to assert the wording was absent, as a proxy for "the
    guide is not assembled as a string". The proxy went wrong when the
    loader started taking the wording as an argument, so it is pinned to
    the thing it was standing for: a label carries no tag, and markup
    built in JavaScript does. Rebuilding
    `'<div class="loading">Loading rule guide</div>'` fails this; passing
    the words to a loader does not.
    """
    for literal in re.findall(r"'([^'\n]*)'|\"([^\"\n]*)\"", _scripts()):
        text = literal[0] or literal[1]
        if "Loading rule guide" in text:
            assert "<" not in text, text


# ---------------------------------------------------------------------------
# The escaping fix
# ---------------------------------------------------------------------------


def test_the_pin_arguments_go_through_json_stringify():
    """Not through esc() into a single-quoted attribute, which is where a
    double quote in a rule name truncated the array."""
    body = _scripts()
    guide = re.search(r"function _appendCaseOnlySections\(.*?\n\}", body,
                      re.S)
    assert guide, "_appendCaseOnlySections"
    source = guide.group(0)
    assert "JSON.stringify" in source
    assert "esc(pinTitle)" not in source
    assert "esc(alertId)" not in source


def test_the_pin_arguments_are_set_as_a_dom_property():
    """A `dataset` assignment stores the value literally, so no HTML
    escaping stands between the JSON and the handler that parses it."""
    body = _scripts()
    guide = re.search(r"function _appendCaseOnlySections\(.*?\n\}", body,
                      re.S)
    assert "dataset.args" in guide.group(0)


def test_the_generated_ids_still_differ_per_alert():
    """Two alerts' guides must not share a rule-guide container, or the
    second load writes into the first one's box."""
    body = _scripts()
    guide = re.search(r"function _appendCaseOnlySections\(.*?\n\}", body,
                      re.S).group(0)
    assert "_railSeq" in guide
    assert "rule-guide-" in guide
    assert "proc-tree-" in guide


def test_the_two_lazy_loaders_are_still_called_with_those_ids():
    body = _scripts()
    guide = re.search(r"function _appendCaseOnlySections\(.*?\n\}", body,
                      re.S).group(0)
    assert "loadRuleGuideInto" in guide
    assert "loadProcessTreeInto" in guide


def test_the_side_panel_is_still_preferred_over_appending():
    """The guide replaces the previous alert's, so selecting a second
    alert must not leave the first one's guide behind."""
    body = _scripts()
    guide = re.search(r"function _appendCaseOnlySections\(.*?\n\}", body,
                      re.S).group(0)
    assert "cpanel-alert-guide" in guide
    assert "replaceChildren" in guide


# ---------------------------------------------------------------------------
# What this finishes
# ---------------------------------------------------------------------------


def test_the_page_owns_no_runtime_writes_outside_the_lazy_sub_panels():
    """Every write left in cases.html belongs to the nine detail
    sub-panels, which are a separate tranche. None is the page's own
    structure any more.
    """
    body = _scripts()
    writes = re.findall(
        r"[^\n]*(?:innerHTML\s*\+?=|insertAdjacentHTML|outerHTML\s*\+?=)[^\n]*",
        body)
    owners = ("container", "el.innerHTML", "host.innerHTML", "body.innerHTML")
    for write in writes:
        assert any(o in write for o in owners), write


def test_the_observable_chip_helpers_went_with_their_last_caller():
    """_obsChipHtml and _enrichableObsTypes existed for
    _alertWidgetExtras, which this tranche converts."""
    body = _scripts()
    assert "_obsChipHtml" not in body
    assert "_enrichableObsTypes" not in body
