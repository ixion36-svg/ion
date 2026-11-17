"""The alert guide, the pin button and the rail's failure message.

The guide and the pin button are markup in the case window's detail
column (`_fragments/cases_panel.html`), which exists once and moves between
Triage and Read. `selectCaseAlert` fills them after the shared alert-detail
component mounts, on an alert object the page already holds. The failure
message is a template, because it is static structure the page shows when
the component did not load.

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
FRAGMENT = ROOT / "src/ion/web/templates/_fragments/cases_panel.html"


def _scripts() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", body,
                                   re.S))
    return re.sub(r"//[^\n]*", "", scripts)


# ---------------------------------------------------------------------------
# The templates
# ---------------------------------------------------------------------------


def test_the_guide_and_pin_are_markup_in_the_detail_column():
    fragment = FRAGMENT.read_text(encoding="utf-8")
    for piece in ('id="cwin-rule-guide"', "cpanel-rule-guide-box",
                  "cpanel-pin-btn", "Investigation guide", "Pin as evidence",
                  "data-cwin-pin"):
        assert piece in fragment, piece
    assert fragment.count('id="cwin-rule-guide"') == 1


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


def _select() -> str:
    found = re.search(r"function selectCaseAlert\(.*?\n\}", _scripts(), re.S)
    assert found, "selectCaseAlert"
    return found.group(0)


def test_the_pin_arguments_go_through_json_stringify():
    """Not through esc() into a single-quoted attribute, which is where a
    double quote in a rule name truncated the array."""
    source = _select()
    assert "JSON.stringify" in source
    assert "esc(pinTitle)" not in source
    assert "esc(alertId)" not in source


def test_the_pin_arguments_are_set_as_a_dom_property():
    """A `dataset` assignment stores the value literally, so no HTML
    escaping stands between the JSON and the handler that parses it."""
    assert "pin.dataset.args = JSON.stringify(" in _select()


def test_the_two_lazy_loaders_are_still_called():
    """The guide on every selection, the process tree when its tab opens."""
    source = _select()
    assert "loadRuleGuideInto(alertId, 'cwin-rule-guide')" in source
    assert "loadProcessTreeInto(alertId, el.id, caseId)" in source


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
