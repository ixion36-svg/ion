"""v0.77.0 — one alert-detail renderer for /alerts and /cases; /cases case-open
rebuilt as a near-full-width inset overlay (concept E).

**The problem.** `/cases` opened a case into a 560px slide-out. At that width an
alert had to be folded away: its parsed fields, rule guide and process tree each
sat behind a separate toggle, on top of the panel's own four tabs. Seeing one
alert fully cost up to **eight clicks** and still showed less than `/alerts`
did — no metadata grid, no message, no MITRE, no AI actions, no Arkime, no raw
data. Analysts left the case to look at the alert properly.

**The duplication underneath it.** `flattenAlertFields`, `_alertFieldsTable` and
`toggleAllAlertFields` had already been copy-pasted into both templates, and the
copies had drifted (class names, `esc` vs `escapeHtml`). Fixing an
alert-rendering bug meant remembering to fix it twice.

**The fix.** `static/js/alert-detail.js` renders an alert once, in two layouts
driven by the same `SECTIONS` list:

  layout 'tabs'     /alerts — eight tabs, one visible. Byte-for-byte the same
                    markup as before, so that page does not change.
  layout 'stacked'  /cases  — every section open in one scroll with sticky
                    jump-links. One click, not eight.

These tests guard the three things most likely to be broken by a later edit:
the duplication coming back, /alerts silently regressing, and the accordions
creeping back into /cases.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES = Path("src/ion/web/templates")
STATIC = Path("src/ion/web/static")


@pytest.fixture(scope="module")
def module_js() -> str:
    return (STATIC / "js" / "alert-detail.js").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def module_css() -> str:
    return (STATIC / "css" / "alert-detail.css").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def alerts() -> str:
    return (TEMPLATES / "alerts.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def cases() -> str:
    return (TEMPLATES / "cases.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def base() -> str:
    return (TEMPLATES / "base.html").read_text(encoding="utf-8")


def _inline_js(html: str) -> str:
    return "\n".join(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S))


def _style(html: str) -> str:
    return "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", html, re.S))


# ── the component exists and is loaded everywhere ────────────────────────


def test_component_files_exist():
    assert (STATIC / "js" / "alert-detail.js").exists()
    assert (STATIC / "css" / "alert-detail.css").exists()


def test_component_loaded_from_base_so_both_pages_get_it(base):
    assert "/static/js/alert-detail.js" in base
    assert "/static/css/alert-detail.css" in base


def test_component_loads_after_app_js(base):
    """It calls escapeHtml()/showToast() from app.js."""
    assert base.index("/static/js/app.js") < base.index("/static/js/alert-detail.js")


def test_one_sections_list_drives_both_layouts(module_js):
    ids = re.findall(r"\{\s*id:\s*'(\w+)'", module_js)
    assert ids == ["related", "timeline", "comments", "case", "sequence",
                   "autoinvestigate", "fields", "rawdata"]


# ── the duplication must not come back ───────────────────────────────────


@pytest.mark.parametrize("fn", ["flattenAlertFields", "_alertFieldsTable",
                                "toggleAllAlertFields", "renderAlertParsedFields",
                                "syntaxHighlightJSON", "loadRelatedAlerts",
                                "switchDetailTab", "renderSystemBadge"])
def test_renderer_defined_exactly_once_across_the_app(fn, alerts, cases, module_js):
    """Each of these was, or was about to become, a second copy. The whole point
    of the component is that there is one."""
    defs = 0
    for src in (_inline_js(alerts), _inline_js(cases), module_js):
        # The module's functions sit inside an IIFE, so they are indented —
        # anchor on start-of-line + optional indent, not column 0.
        defs += len(re.findall(rf"^\s*(?:async )?function {re.escape(fn)}\b", src, re.M))
    assert defs == 1, f"{fn} is defined {defs} times — the copies are back"


def test_component_exposes_what_the_pages_still_call(module_js):
    for name in ("switchDetailTab", "loadRelatedAlerts", "renderSystemBadge",
                 "openAIChatWithContext", "flattenAlertFields", "syntaxHighlightJSON"):
        assert re.search(rf"window\.{re.escape(name)}\s*=", module_js), name


def test_component_takes_capabilities_as_options_not_page_globals(module_js):
    """aiAvailable/arkimeEnabled were alerts.html page globals. If the component
    reads them bare it works on /alerts and silently degrades on /cases."""
    body = re.sub(r"/\*.*?\*/", "", module_js, flags=re.S)
    body = re.sub(r"^\s*//.*$", "", body, flags=re.M)
    for flag in ("aiAvailable", "arkimeEnabled"):
        bare = re.findall(rf"(?<!_opts\.)(?<!\w)(?<!\.){flag}\b", body)
        # the only permitted mentions are as opts keys
        assert all("_opts" in body[max(0, m.start() - 6):m.start()]
                   for m in re.finditer(rf"\b{flag}\b", body)) or not bare, \
            f"{flag} is read as a bare global"


# ── /alerts must not regress ─────────────────────────────────────────────


def test_alerts_still_uses_the_tabs_layout(alerts):
    js = _inline_js(alerts)
    assert "ionAlertDetail.mount(" in js
    assert "layout: 'tabs'" in js


def test_alerts_keeps_its_page_specific_wiring(alerts):
    """Modal, investigation timer and triage stay on the page — they are not
    the component's business."""
    js = _inline_js(alerts)
    fn = js[js.index("async function showAlertDetail"):]
    fn = fn[:fn.index("\n}")]
    for bit in ("alert-detail-modal", "startInvestigationTimer", "loadTriage"):
        assert bit in fn, bit


def test_component_css_moved_out_of_alerts_page(alerts, module_css):
    """The first attempt rendered unstyled on /cases because .alert-meta-grid
    only existed inside the /alerts <style> block."""
    style = _style(alerts)
    for cls in ("alert-meta-grid", "detail-tab-btn", "alert-message-box", "triage-bar"):
        assert not re.search(rf"\.{cls}\s*[,{{]", style), f".{cls} still page-local"
        assert re.search(rf"\.{cls}\s*[,{{]", module_css), f".{cls} missing from the component"


def test_alerts_style_block_is_not_corrupted(alerts):
    """Moving rules out with a regex that cannot see nesting tore the closing
    braces off @media wrappers the first time. Guard the invariant."""
    style = _style(alerts)
    assert style.count("{") == style.count("}")
    assert "@media" in style, "the @media blocks must be left where they were"


def test_component_css_is_balanced(module_css):
    assert module_css.count("{") == module_css.count("}")


# ── /cases: concept E ────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def workspace_css() -> str:
    """v0.79.0: the panel chrome moved out of cases.html into a shared sheet
    when /documents adopted the same shape. Same move the alert-detail CSS made
    at v0.77.0, for the same reason — the second page to use it rendered
    unstyled while the rules lived in the first page's <style> block."""
    return (STATIC / "css" / "ion-workspace.css").read_text(encoding="utf-8")


def _strip_css_comments(css: str) -> str:
    """Comments describing a selector are not a definition of it.

    Third time this has produced a false positive in this suite — a note
    mentioning `.case-panel { width: 100vw }` read as the rule still existing.
    """
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def _top_level_rule(css: str, selector: str) -> str:
    """The body of a rule whose selector starts at column 0.

    Anchoring on the first occurrence finds the copy nested inside an @media
    block, whose declarations are the RESPONSIVE override (inset: 0), not the
    base rule.
    """
    m = re.search(rf"^{re.escape(selector)}[^{{]*\{{(.*?)\}}", css, re.M | re.S)
    assert m, f"{selector} not found as a top-level rule"
    return m.group(1)


def test_case_panel_is_an_inset_overlay_not_a_narrow_slideout(workspace_css):
    panel = _top_level_rule(_strip_css_comments(workspace_css), ".ion-ws-panel,")
    assert "inset: 22px" in panel
    assert "560px" not in panel, "the 560px slide-out is back"


def test_case_panel_has_a_two_column_workspace(workspace_css):
    assert ".cpanel-workspace" in workspace_css
    ws = _top_level_rule(_strip_css_comments(workspace_css), ".ion-ws-grid,")
    assert "grid-template-columns: 300px 1fr" in ws


def test_panel_chrome_is_defined_once_not_copied(cases, workspace_css):
    """The move is only worth anything if the rules LEFT cases.html. Defining
    them in both places is the duplication this exists to remove — and it is
    invisible, because the page still looks right."""
    style = _strip_css_comments(_style(cases))
    for sel in (".case-panel {", ".cpanel-workspace {", ".case-panel-body {",
                ".cpanel-rail-alert {"):
        assert sel not in style, f"{sel} is still defined in cases.html as well"
        assert sel.rstrip(" {") in workspace_css, f"{sel} is missing from the shared sheet"


def test_shared_sheet_keeps_both_selector_names(workspace_css):
    """Each rule carries the generic .ion-ws-* name /documents uses AND the
    .case-panel/.cpanel-* name /cases already had. Drop either side and one of
    the two pages renders unstyled."""
    for generic, existing in ((".ion-ws-panel", ".case-panel"),
                              (".ion-ws-grid", ".cpanel-workspace"),
                              (".ion-ws-rail-item", ".cpanel-rail-alert"),
                              (".ion-ws-body", ".case-panel-body")):
        assert generic in workspace_css, f"{generic} missing — /documents loses its chrome"
        assert existing in workspace_css, f"{existing} missing — /cases loses its chrome"


def test_both_pages_get_the_shared_sheet(base):
    assert "/static/css/ion-workspace.css" in base


def test_cases_uses_the_stacked_layout(cases):
    js = _inline_js(cases)
    assert "window.ionAlertDetail.mount(" in js
    assert "layout: 'stacked'" in js


def test_selecting_an_alert_needs_no_refetch(cases):
    """The rail stashes the alert object so selection is instant."""
    js = _inline_js(cases)
    assert "_railAlerts[alertId] = a" in js
    assert "_railAlerts[alertId]" in js


def test_first_alert_is_rendered_on_open(cases):
    """Opening a case to an empty right-hand column would reintroduce the very
    click this rework removed."""
    js = _inline_js(cases)
    assert "selectCaseAlert(firstAlert.es_alert_id" in js


def test_case_opens_on_the_alerts_tab(cases):
    js = _inline_js(cases)
    assert "let _currentPanelTab = 'alerts';" in js


# ── v0.77.1: the rail is ordered by severity ─────────────────────────────


def test_rail_is_sorted_by_severity(cases):
    """The alert that auto-renders should be the one worth looking at first,
    not whichever the API happened to return first."""
    js = _inline_js(cases)
    assert "alerts.sort(" in js
    assert "_sevOf" in js


def test_rail_sort_reuses_the_board_severity_scale(cases):
    """A second severity ordering would be one more thing to keep in step."""
    js = _inline_js(cases)
    assert js.count("_sevRank = {") == 1, "a second severity scale was declared"
    assert "_sevRank[a.priority || a.severity || c.severity]" in js


def test_rail_sort_is_in_place_so_both_consumers_agree(cases):
    """openCaseDetail reads c.alerts[0] after renderPanelContent returns and
    passes index 0 to selectCaseAlert. If the sort produced a local copy, the
    rail would show one alert selected while the detail column rendered a
    different one — silently, and only on cases whose API order is not already
    severity-descending."""
    js = _inline_js(cases)
    # sorting the same array the caller holds, not a slice/copy of it
    assert "const alerts = c.alerts || [];" in js
    sort_at = js.index("alerts.sort(")
    decl_at = js.index("const alerts = c.alerts || [];")
    between = js[decl_at:sort_at]
    for copier in (".slice(", ".concat(", "[...alerts]", "Array.from("):
        assert copier not in between, f"alerts was copied via {copier} before sorting"


# ── the accordions must stay gone ────────────────────────────────────────


@pytest.mark.parametrize("gone", ["toggleAlertFields", "toggleRuleGuide", "toggleProcessTree"])
def test_alert_accordions_are_retired(gone, cases):
    js = _inline_js(cases)
    js = re.sub(r"^\s*//.*$", "", js, flags=re.M)   # the removal note names them
    assert not re.search(rf"^(?:async )?function {gone}\b", js, re.M), \
        f"{gone} is back — an alert section is behind a toggle again"
    assert f'data-click-action="{gone}"' not in cases


def test_rule_guide_and_process_tree_load_without_a_click(cases):
    js = _inline_js(cases)
    assert "async function loadRuleGuideInto" in js
    assert "async function loadProcessTreeInto" in js
    assert "loadRuleGuideInto(alertId, rgId)" in js
    assert "loadProcessTreeInto(alertId, ptId, caseId)" in js


def test_stacked_layout_forces_every_section_open(module_css):
    """`.detail-tab-content` is display:none by default so the tabs layout can
    hide seven of eight. In the stacked layout that rule must not apply."""
    block = module_css[module_css.index(".iad-section .detail-tab-content"):]
    block = block[:block.index("}")]
    assert "display: block" in block


def test_jump_links_scroll_rather_than_hide(module_js):
    """A jump-link that hid the other sections would be a tab wearing a hat."""
    fn = module_js[module_js.index("function showSection"):]
    fn = fn[:fn.index("\n  }")]
    assert "scrollIntoView" in fn
    assert "display" not in fn, "showSection is hiding things instead of scrolling"


def test_no_duplicate_top_level_declarations_in_cases(cases):
    js = _inline_js(cases)
    names = re.findall(r"^(?:const|let|var|function|async function)\s+(\w+)", js, re.M)
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, f"duplicate top-level declaration(s): {dupes}"


def test_dead_fields_dropdown_machinery_is_gone(cases):
    """Seven functions plus two lookup maps served the old dropdown. Leaving
    them behind is how the next copy-paste starts."""
    js = _inline_js(cases)
    for dead in ("_extractedValuesBlock", "renderFlatAlertFields", "addFieldsAsEvidence",
                 "_alertObsByFieldsId", "_fieldsIdToCaseId", "_alertKeyFieldsByFieldsId"):
        assert not re.search(rf"^(?:const|let|var|function|async function)\s+{dead}\b", js, re.M), dead
