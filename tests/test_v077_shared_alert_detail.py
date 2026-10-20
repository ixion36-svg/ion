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
def alerts_page_css() -> str:
    """Where /alerts' own rules live.

    Out of the template's <style> block at the redesign, into
    alerts-page.css, and from there into the one build -- nested under
    body[data-page="alerts"] in frontend/ion-pages.css. Only that block is
    returned: the file carries every page, and handing back the whole thing
    would quietly widen every assertion made against this fixture.
    """
    whole = Path("frontend/ion-pages.css").read_text(encoding="utf-8")
    opener = 'body[data-page="alerts"] {'
    # /alerts has two blocks: alerts-queue.css and alerts-page.css were
    # separate sheets and were retired separately. Reading only the first
    # silently halves what this fixture covers.
    blocks, at = [], 0
    while (found := whole.find(opener, at)) != -1:
        start = found + len(opener)
        depth, i = 1, start
        while depth:
            if whole[i] == "{":
                depth += 1
            elif whole[i] == "}":
                depth -= 1
            i += 1
        blocks.append(whole[start:i - 1])
        at = i
    assert blocks, "the alerts scope block is gone"
    return "\n".join(blocks)


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
    """The canonical SECTIONS array is the only section list.

    Asserting on every `id:` literal in the file was too literal: the v2
    layout legitimately derives extra entries (Comments relabelled to Notes,
    a v2-only Guide tab). What must hold is that the canonical list is intact
    and that both layouts read it through _visibleSections() rather than
    declaring a second list.
    """
    canonical = re.search(r"var SECTIONS = \[(.*?)\];", module_js, re.S)
    assert canonical, "canonical SECTIONS array not found"
    ids = re.findall(r"\{\s*id:\s*'(\w+)'", canonical.group(1))
    assert ids == ["related", "timeline", "comments", "case", "sequence",
                   "autoinvestigate", "fields", "rawdata"]

    # Every layout builder derives from the canonical list rather than
    # declaring its own; slice each body by index so the check does not
    # depend on a multi-line regex.
    for fn in ("_sectionsHtml", "_sectionsHtmlV2"):
        marker = "function " + fn + "(alert) {"
        at = module_js.find(marker)
        assert at != -1, fn + " not found"
        # bound the slice at the next top-level function so the check
        # cannot be satisfied by the neighbouring builder
        nxt = module_js.find(chr(10) + "  function ", at + len(marker))
        body = module_js[at:nxt if nxt != -1 else len(module_js)]
        assert "var SECTIONS = _visibleSections()" in body, (
            fn + " must assign SECTIONS from the canonical list"
        )
        assert "var SECTIONS = [" not in body, (
            fn + " must not declare a second section list"
        )


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


def test_alerts_uses_the_stacked_layout(alerts):
    # /alerts moved from tabs to the stacked sections /cases proved, so the
    # two hosts render the alert through one code path.
    js = _inline_js(alerts)
    assert "ionAlertDetail.mount(" in js
    assert "layout: 'stacked'" in js


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


def test_the_alerts_page_has_no_inline_style_block_left(alerts):
    """The half of the test above that looks at the page is vacuous now, and
    a vacuous assertion is worth replacing with the stronger one it became.

    The UI redesign moved every rule out of the template, so the question is
    no longer whether four classes left the <style> block but whether the
    block exists at all. It does not, and a new one would be a page-local
    rule that /cases could not see, which is the regression the test above
    was written for."""
    assert _style(alerts) == ""


def test_the_alerts_page_stylesheet_is_not_corrupted(alerts_page_css):
    """Moving rules out with a regex that cannot see nesting tore the closing
    braces off @media wrappers the first time. Guard the invariant.

    This guarded the template's <style> block until the redesign moved those
    rules to alerts-page.css, at which point it asserted @media inside a
    block that no longer existed and failed for a move it should have
    followed. The invariant belongs to wherever the rules live."""
    assert alerts_page_css.count("{") == alerts_page_css.count("}")
    assert "@media" in alerts_page_css, "the @media blocks must survive the move"


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


def test_cases_uses_the_tabbed_layout(cases):
    """SUPERSEDED at v0.79.5 — was test_cases_uses_the_stacked_layout.

    v0.77.0 chose stacked so that seeing an alert fully cost one click instead
    of eight. In production that turned out to have two costs the design did not
    anticipate: opening every section at once made ONE case-alert click fan out
    to nine requests, and — because the component was throwing ReferenceError on
    /cases (see test_v079_5_case_alert_detail.py) — it put every broken section
    on screen simultaneously, as a wall of spinners that could not be scrolled
    past because the collapsed stack fitted in one viewport.

    Tabs with per-tab lazy loading keep the fix (nothing is behind an accordion;
    the first tab is populated on open) while showing one section at a time.
    The click-count win is preserved by _visibleSections + the first-tab loader,
    not by rendering everything.
    """
    js = _inline_js(cases)
    assert "window.ionAlertDetail.mount(" in js
    assert "layout: 'tabs'" in js
    assert "layout: 'stacked'" not in js


def test_selecting_an_alert_needs_no_refetch(cases):
    """The rail stashes the alert object so selection is instant.

    Still true and still the page's job: selectCaseAlert hands a whole
    alert to the shared component, so the objects have to be to hand. Only
    the key changed, to fall back to 'unknown' rather than index by
    undefined.
    """
    js = _inline_js(cases)
    assert "_railAlerts[a.es_alert_id || 'unknown'] = a" in js
    assert "_railAlerts[alertId]" in js


def test_first_alert_is_rendered_on_open(cases):
    """Opening a case to an empty right-hand column would reintroduce the
    very click this rework removed.

    The fragment names the first alert in data-first-alert-id and the page
    reads it back, rather than the page picking c.alerts[0] for itself.
    test_the_rail_order_and_the_detail_column_cannot_disagree below says
    why that is the stronger arrangement.
    """
    js = _inline_js(cases)
    assert "workspace.dataset.firstAlertId" in js
    assert "selectCaseAlert(firstAlertId, 0, c.id)" in js


def test_case_opens_on_the_alerts_tab(cases):
    js = _inline_js(cases)
    assert "let _currentPanelTab = 'alerts';" in js


# ── v0.77.1: the rail is ordered by severity ─────────────────────────────


def _panel_module() -> str:
    return (Path(__file__).resolve().parent.parent / "src" / "ion" / "web"
            / "ui" / "cases.py").read_text(encoding="utf-8")


def test_rail_is_sorted_by_severity():
    """The alert that auto-renders should be the one worth looking at first,
    not whichever the API happened to return first.

    The panel is a fragment now, so the order is the server's. It was
    alerts.sort() over _sevOf in the page.
    """
    module = _panel_module()
    assert "PANEL_SEV_RANK" in module
    assert '"critical": 0' in module and '"low": 3' in module


def test_rail_sort_reuses_the_board_severity_scale():
    """A second severity ordering would be one more thing to keep in step.

    The page reused the board's _sevRank rather than declaring its own,
    and the module says it inherited that decision. Asserting the count is
    what keeps a second table from being added quietly.
    """
    module = _panel_module()
    assert module.count("PANEL_SEV_RANK: dict[str, int] = {") == 1, \
        "a second severity scale was declared"
    assert "info" in module, \
        "the scale needs a rank for a severity the board does not show"


def test_the_rail_order_and_the_detail_column_cannot_disagree(cases):
    """This was test_rail_sort_is_in_place_so_both_consumers_agree.

    openCaseDetail read c.alerts[0] after renderPanelContent returned and
    passed index 0 to selectCaseAlert, so the sort had to mutate the
    caller's own array. A slice or a spread anywhere in between would have
    shown one alert selected in the rail while the detail column rendered
    a different one, silently, and only on cases whose API order was not
    already severity-descending. The test enumerated four ways of copying
    an array and hoped it had thought of them all.

    None of that can happen now, and not because the copying was fixed.
    The fragment decides the order and names the first alert in
    data-first-alert-id, so there is one source for both and no second
    derivation to diverge from it. Asserting the page does not pick for
    itself is what holds that.
    """
    js = _inline_js(cases)
    assert "workspace.dataset.firstAlertId" in js
    # Comments stripped: the note above openCaseDetail quotes the old
    # c.alerts[0] read to explain why it went, and the assertion is about
    # code.
    code = re.sub(r"^\s*//.*$", "", js, flags=re.M)
    assert "c.alerts[0]" not in code
    assert "alerts.sort(" not in code, \
        "the page is deriving the rail order again, so the two can diverge"


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
