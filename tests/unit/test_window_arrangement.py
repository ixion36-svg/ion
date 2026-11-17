"""The arranged window: sections an analyst moves between columns, folds and
hides, with one arrangement remembered per kind of window.

The case window had this as ~330 lines of inline script addressed to
#case-panel. The alert window needed the same thing, so it moved to
static/js/ion-arrange.js and both windows configure it. What is pinned:

  * there is one implementation, and neither page carries a copy;
  * the merge that keeps a saved place for a section the current window does
    not have, run for real under node;
  * each window keeps its own storage key, so the case arrangement people
    already have is read back unchanged and the alert one cannot overwrite it;
  * the alert component leaves folding to the host that arranges it.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "src/ion/web"
ARRANGE = WEB / "static/js/ion-arrange.js"
ARRANGE_JS = ARRANGE.read_text(encoding="utf-8")
CASES = (WEB / "templates/cases.html").read_text(encoding="utf-8")
ALERTS = (WEB / "templates/alerts.html").read_text(encoding="utf-8")
WINDOW_JS = (WEB / "static/js/alerts-window.js").read_text(encoding="utf-8")
CASE_WINDOW_JS = (WEB / "static/js/case-window.js").read_text(encoding="utf-8")
DETAIL_JS = (WEB / "static/js/alert-detail.js").read_text(encoding="utf-8")
WORKSPACE_CSS = (WEB / "static/css/ion-workspace.css").read_text(encoding="utf-8")


def _merge(now: dict, saved: dict | None) -> dict:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not on PATH")
    program = (
        "global.window = {}; global.document = {};"
        f"require({json.dumps(str(ARRANGE))});"
        f"const out = window.ionArrange.mergeLayout({json.dumps(now)}, {json.dumps(saved)});"
        "process.stdout.write(JSON.stringify(out));"
    )
    result = subprocess.run([node, "-e", program], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# The merge
# ---------------------------------------------------------------------------

def test_a_section_this_window_lacks_keeps_its_saved_column_and_neighbour():
    """An alert with no Sequence section is arranged; Sequence was saved after
    Timeline on the right. Saving must not forget that."""
    now = {"cols": {"centre": ["fields"], "right": ["related", "timeline", "comments"]},
           "hidden": [], "collapsed": []}
    saved = {"cols": {"centre": ["fields"], "right": ["related", "timeline", "sequence", "comments"]},
             "hidden": [], "collapsed": []}
    assert _merge(now, saved)["cols"]["right"] == ["related", "timeline", "sequence", "comments"]


def test_an_absent_sections_hidden_and_folded_flags_survive():
    now = {"cols": {"centre": ["fields"]}, "hidden": [], "collapsed": ["fields"]}
    saved = {"cols": {"centre": ["fields", "guide"]}, "hidden": ["guide"], "collapsed": ["guide"]}
    merged = _merge(now, saved)
    assert merged["hidden"] == ["guide"]
    assert merged["collapsed"] == ["fields", "guide"]


def test_a_present_section_takes_the_place_it_has_now_not_the_saved_one():
    """Dragging Guide from centre to left has to stick: the saved copy in
    centre must not be put back beside the moved one."""
    now = {"cols": {"left": ["guide"], "centre": ["fields"]}, "hidden": [], "collapsed": []}
    saved = {"cols": {"left": [], "centre": ["guide", "fields"]}, "hidden": ["guide"], "collapsed": []}
    merged = _merge(now, saved)
    assert merged["cols"] == {"left": ["guide"], "centre": ["fields"]}
    # Present and shown now, so the saved hidden flag does not come back.
    assert merged["hidden"] == []


def test_a_column_only_the_saved_layout_has_is_carried():
    now = {"cols": {"centre": ["fields"]}, "hidden": [], "collapsed": []}
    saved = {"cols": {"full": ["alerts-in-case"]}, "hidden": [], "collapsed": []}
    assert _merge(now, saved)["cols"] == {"centre": ["fields"], "full": ["alerts-in-case"]}


@pytest.mark.parametrize("saved", [None, {}, {"hidden": ["x"]}])
def test_nothing_usable_saved_leaves_the_current_layout_as_it_is(saved):
    now = {"cols": {"centre": ["fields"]}, "hidden": [], "collapsed": []}
    assert _merge(dict(now), saved) == now


# ---------------------------------------------------------------------------
# One implementation
# ---------------------------------------------------------------------------

def test_the_alert_window_loads_the_module_and_neither_page_keeps_a_copy():
    """The case window stopped arranging sections when it became two
    layouts (Triage and Read, static/js/case-window.js), so only the alert
    window loads the module now."""
    assert "/static/js/ion-arrange.js?v={{ ion_version }}" in ALERTS
    assert "ion-arrange.js" not in CASES
    for page in (CASES, ALERTS):
        # The functions the inline copy was made of.
        for gone in ("function pmSaveLayout", "function pmArrange", "function pmWireDrag",
                     "function pmInjectHeaderTools", "function pmFitCols"):
            assert gone not in page, gone
    assert "ionArrange.create({" not in CASES
    assert "window.ionArrange.create({" in WINDOW_JS


def test_the_module_names_no_page():
    """It takes its section, title and tools selectors as configuration. A
    case or alert class name in here is the start of a second fork."""
    code = re.sub(r"/\*.*?\*/", "", ARRANGE_JS, flags=re.S)
    for name in ("cpanel", "case-panel", "iad-", "alert-window", "allCases"):
        assert name not in code, name


def test_the_module_is_loaded_before_the_script_that_configures_it():
    assert ALERTS.index("/static/js/ion-arrange.js") < ALERTS.index("/static/js/alerts-window.js")


def test_each_window_keeps_its_own_storage_key():
    assert "storageKey: 'ion-alert-window-layout-v1'" in WINDOW_JS
    assert "ion-case-window-layout" not in CASES
    assert "var MODE_KEY = 'ion-case-window-mode';" in CASE_WINDOW_JS


def test_the_case_window_keeps_previous_and_next_case():
    """The arranger drew these two buttons into the case header; the header
    carries them itself now."""
    for title in ("Previous case", "Next case"):
        assert f'title="{title}"' in CASES, title
    assert CASES.count('data-click-action="pmStepCase"') == 2
    assert "function pmStepCase(delta)" in CASES


def test_presets_and_reset_place_sections_in_rendered_order():
    """Reset used to walk the sections in the order a drag had left them, so
    it restored the columns and kept the shuffle."""
    preset = ARRANGE_JS[ARRANGE_JS.index("function applyPreset(id)"):]
    preset = preset[:preset.index("\n    }")]
    assert "order[a.dataset.section] - order[b.dataset.section]" in preset
    reset = ARRANGE_JS[ARRANGE_JS.index("reset.addEventListener('click'"):]
    reset = reset[:reset.index("});")]
    assert "localStorage.removeItem(cfg.storageKey)" in reset
    assert "applyPreset(cfg.presets[0].id)" in reset


def test_the_arranged_css_is_not_addressed_to_the_case_panel():
    """A rule scoped to .case-panel would leave the alert window's grid
    unstyled: one column, no folding."""
    assert re.search(r"^\.pm-cols \{", WORKSPACE_CSS, re.M)
    assert ".case-panel.page-mode .pm-cols" not in WORKSPACE_CSS
    assert ".pm-section.pm-collapsed > :not(.pm-sec-head) { display: none; }" in WORKSPACE_CSS
    assert "sec.classList.add('pm-section')" in ARRANGE_JS


# ---------------------------------------------------------------------------
# The alert window's use of it
# ---------------------------------------------------------------------------

def test_the_alert_window_arranges_the_components_sections_with_their_own_heads():
    config = WINDOW_JS[WINDOW_JS.index("window.ionArrange.create({"):]
    config = config[:config.index("});")]
    assert "candidates: '.iad-section'" in config
    # The section already has a head and a fold class; a second head or a
    # second fold class would give two chevrons and two states.
    assert "headOf: function (sec) { return sec.querySelector('.iad-sec-head'); }" in config
    assert "collapsedClass: 'iad-folded'" in config
    assert "defaultCollapsed: function (key) { return key === 'rawdata'; }" in config


def test_the_alert_presets_are_triage_wide_and_focus():
    block = WINDOW_JS[WINDOW_JS.index("var PRESETS = ["):WINDOW_JS.index("// A hidden section's jump link")]
    assert re.findall(r"id: '(\w+)', label: '(\w+)'", block) == [
        ("triage", "Triage"), ("wide", "Wide"), ("focus", "Focus")]


def test_the_component_leaves_folding_to_a_host_that_arranges():
    """With both the component's fold action and the arranger's click handler
    on one head, a click folded the section and unfolded it again."""
    assert "var foldAction = _opts.arrange ? '' : ' data-click-action=\"ionAlertDetailFold\"';" in DETAIL_JS
    mount = ALERTS[ALERTS.index("ionAlertDetail.mount(document.getElementById('alert-detail-body')"):]
    mount = mount[:mount.index("});")]
    assert "arrange: true" in mount and "layout: 'stacked'" in mount
    # /cases mounts the component in tabs and does not ask for this.
    assert "arrange:" not in CASES


def test_a_hidden_sections_jump_link_is_hidden_with_it():
    sync = WINDOW_JS[WINDOW_JS.index("function syncJumpLinks()"):]
    sync = sync[:sync.index("\n  }")]
    assert "link.hidden = !!sec && sec.hidden" in sync
    assert "onChange: syncJumpLinks" in WINDOW_JS
