"""v0.79.5 — the shared alert-detail component actually works on /cases.

**What was broken.** v0.77.0 extracted alert-detail.js out of alerts.html but
left it referencing helpers that only THAT page declares. On /cases they were
undefined, so every section that touched one threw ReferenceError and stuck on
"Loading..." forever: triage, fields, related, timeline, comments. The catch
handler in loadAlertParsedFields called one of them too, so the error handler
threw while handling the error — which is why it surfaced as "Uncaught (in
promise)" and a spinner that never resolved rather than a visible failure.

**Why it looked like a scroll bug.** /cases used the stacked layout, where the
section headings are jump-links that scroll. With every section collapsed to a
one-line spinner the whole stack fitted in roughly one viewport, so clicking
"Timeline" had nowhere to scroll and read as a dead control.

**The fixes.** The component owns its helpers (host page preferred where it has
a richer one); /cases uses tabs with per-tab lazy loading — two requests on open
instead of nine; sections the host cannot populate are not rendered at all; and
the rule guide moves to a side panel, since it is reference you read WHILE
working a tab.

The undefined-symbol sweep is the load-bearing test here: it is a whole CLASS of
bug, it fails silently in production, and a static scan missed two instances
(`_alertParsedKeyFields`, an assignment target rather than a call) that only a
live render caught.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

JS = Path("src/ion/web/static/js/alert-detail.js")
CASES = Path("src/ion/web/templates/cases.html")
DOCS = Path("src/ion/web/templates/documents.html")
CSS = Path("src/ion/web/static/css/ion-workspace.css")

# Declared ONLY in alerts.html. Every one of these was reached from the shared
# component and blew up on /cases.
PAGE_ONLY = [
    "triageCache",
    "calculateSimilarity",
    "renderTimeline",
    "_alertExtractedValuesBlock",
    "_alertExtractedObs",
    "ALERT_KEY_PREFIXES",
    "_AUTOINV_VERDICT_CLASS",
    "_autoinvRefBadges",
    "formatAIContent",
    "getAlertPayload",
    "showNotification",
    "formatDate",
    "_alertParsedKeyFields",
    "renderCommentsTab",
]


def _strip(js: str) -> str:
    """Comments in this file quote the very identifiers under test."""
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    return re.sub(r"^\s*//.*$", "", js, flags=re.M)


@pytest.fixture(scope="module")
def js() -> str:
    return _strip(JS.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def cases_js() -> str:
    html = CASES.read_text(encoding="utf-8")
    return _strip("\n".join(
        re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S)
    ))


# ── no bare cross-page references ────────────────────────────────────────


@pytest.mark.parametrize("name", PAGE_ONLY)
def test_page_only_symbols_are_never_referenced_bare(name, js):
    """A bare reference resolves on /alerts and throws on /cases — the exact
    shape of this bug.

    Exactly three outcomes are safe, and the component must be in one of them:
      1. it declares the symbol itself (bare use then binds to its own);
      2. every use sits inside `_page(function () { return X; })`, which
         catches the ReferenceError;
      3. it never mentions the symbol at all.
    Anything else throws on a host page that lacks the declaration.
    """
    if re.search(r"\b(?:var|let|const|function)\s+" + re.escape(name) + r"\b", js):
        return  # (1) component-owned

    body = js.replace(f"return {name};", "")  # drop the guarded probes
    bare = re.findall(r"(?<![.\w$'\"])" + re.escape(name) + r"(?![\w$])", body)
    assert not bare, (
        f"{name} is referenced without a guard ({len(bare)}x). It is declared "
        "only in alerts.html, so this throws ReferenceError on /cases and the "
        "section sticks on 'Loading...' with no visible error."
    )


def test_the_probe_catches_reference_errors(js):
    fn = js[js.index("function _page(probe)"):]
    fn = fn[:fn.index("\n  function _pageTriageCache")]
    assert "try" in fn and "catch" in fn


def test_the_probe_does_not_use_eval(js):
    """CSP has no 'unsafe-eval'; a string-based typeof probe would be blocked at
    runtime and only on the deployed page, never in a test."""
    assert "eval(" not in js


# ── the capability contract ──────────────────────────────────────────────


def test_sections_can_be_restricted_by_the_host(js):
    assert "function _visibleSections(" in js
    assert "_opts.sections" in js


def test_default_is_every_section(js):
    """/alerts passes no `sections`, and must keep all of them."""
    fn = js[js.index("function _visibleSections("):]
    fn = fn[:fn.index("\n  function _sectionsHtml(")]
    assert "if (!allow || !allow.length) return SECTIONS;" in fn


def test_cases_omits_only_what_it_cannot_fill(cases_js):
    """The triage bar's loader lives in alerts.html and reaches into its state.
    Rendering it on /cases produced a permanent spinner."""
    call = cases_js[cases_js.index("window.ionAlertDetail.mount(host, forDetail"):]
    call = call[:call.index("});")]
    assert "triageBar: false" in call
    assert "'comments'" in call, "comments IS loadable (GET /triage) and should stay"
    assert "'case'" not in call, "a 'Case' tab inside a case is circular"


def test_the_triage_bar_is_actually_gated(js):
    assert "_opts.triageBar === false" in js


# ── tabs + lazy loading ──────────────────────────────────────────────────


def test_cases_uses_tabs(cases_js):
    call = cases_js[cases_js.index("window.ionAlertDetail.mount(host, forDetail"):]
    call = call[:call.index("});")]
    assert "layout: 'tabs'" in call
    assert "layout: 'stacked'" not in call


def test_mount_loads_only_the_visible_section(js):
    """Stacked loaded everything up front — that is the nine-request burst."""
    fn = js[js.index("function mount(container, alert, opts)"):]
    fn = fn[:fn.index("\n  function _loadSection(")]
    assert "_visibleSections()[0]" in fn
    assert "_loadSection(first.id, alert)" in fn


@pytest.mark.parametrize("section", ["related", "timeline", "comments", "fields", "rawdata"])
def test_each_section_has_a_lazy_loader(section, js):
    fn = js[js.index("function switchDetailTab("):]
    fn = fn[:fn.index("\n  function _renderHead(")]
    assert f"'{section}'" in fn, f"{section} tab never loads when clicked"


def test_related_and_timeline_share_one_request(js):
    """They are filled by the same /related response; two fetches would be
    waste, and the second would overwrite the first mid-render."""
    assert "_relatedLoaded" in js
    fn = js[js.index("function switchDetailTab("):]
    fn = fn[:fn.index("\n  function _renderHead(")]
    assert "tabId === 'related' || tabId === 'timeline'" in fn


def test_switching_alert_resets_the_lazy_flags(js):
    """Otherwise the second alert you click shows the first alert's data."""
    fn = js[js.index("function mount(container, alert, opts)"):]
    fn = fn[:fn.index("\n  function _loadSection(")]
    assert "_relatedLoaded = false;" in fn
    assert "_commentsLoaded = false;" in fn


def test_having_the_raw_document_renders_it_rather_than_skipping(js):
    """The guard used to be `&& !_current.raw_data`, so once hydration or the
    Fields tab had populated it, Raw Data sat on its placeholder holding the
    document it was refusing to show. Found by the live mockup, not by review.
    """
    fn = js[js.index("function switchDetailTab("):]
    fn = fn[:fn.index("\n  function _renderHead(")]
    assert "querySelector('.loading') && _current.raw_data" in fn
    raw_into = js[js.index("function _loadRawInto("):]
    raw_into = raw_into[:raw_into.index("\n  function _observeSections(")]
    assert "if (alert.raw_data) { el.innerHTML = syntaxHighlightJSON(alert.raw_data); return; }" in raw_into


def test_comments_come_from_the_triage_endpoint(js):
    """/comments is POST-only; the list arrives on GET /triage as {triage,
    comments}. Getting this wrong means an endless spinner, not a 404."""
    fn = js[js.index("function loadAlertComments("):]
    fn = fn[:fn.index("\n  function ionAlertAddComment(")]
    assert "/triage" in fn
    assert "data.comments" in fn


def test_the_comment_action_does_not_collide_with_the_page(js):
    """alerts.html declares its own top-level addComment(); whichever script
    loaded last would win if both claimed window.addComment."""
    assert "window.ionAlertAddComment" in js
    assert "window.addComment =" not in js


# ── CSP: no inline style attributes ──────────────────────────────────────


@pytest.mark.parametrize("path", [CASES, DOCS])
def test_no_inline_style_attributes(path):
    """CSP sets `style-src-attr 'none'` (v0.31.21). An inline style= is refused
    outright — the rail severity dots rendered colourless because of one."""
    src = path.read_text(encoding="utf-8")
    src = re.sub(r"<!--.*?-->", "", src, flags=re.S)
    src = re.sub(r"^\s*(//|/\*).*$", "", src, flags=re.M)
    hits = re.findall(r"""(?<![-\w])style=["'][^"']*["']""", src)
    assert not hits, f"{path.name} reintroduced inline style attributes: {hits[:3]}"


def test_severity_stripe_uses_a_class(js=None):
    css = CSS.read_text(encoding="utf-8")
    for sev in ("critical", "high", "medium", "low"):
        assert f".rail-sev-{sev}" in css


# ── the guide side panel ─────────────────────────────────────────────────


def test_the_guide_renders_into_the_aside(cases_js):
    fn = cases_js[cases_js.index("function _appendCaseOnlySections("):]
    fn = fn[:fn.index("\nlet _railSeq")]
    assert "cpanel-alert-guide" in fn
    assert "iad-section" not in fn, (
        "iad-section is STACKED-layout markup; with the component on tabs it "
        "would dangle below the tab strip with no stack to belong to"
    )


def test_the_aside_exists_in_the_workspace(cases_js):
    assert 'aside class="cpanel-guide" id="cpanel-alert-guide"' in cases_js


def test_the_guide_shares_the_coalesced_raw_request(cases_js):
    """Showing it beside the tabs must not cost an extra Elasticsearch read."""
    fn = cases_js[cases_js.index("async function loadRuleGuideInto"):]
    fn = fn[:fn.index("\n}")]
    assert "window.ionAlertDetailFetchRaw" in fn


def test_the_workspace_collapses_on_narrow_screens():
    """Three columns below ~1400px squeeze the guide to an unreadable strip;
    below 1100px there is not room for the rail column either."""
    css = CSS.read_text(encoding="utf-8")
    assert "@media (max-width: 1400px)" in css
    tail = css[css.index("@supports not selector(:has(*))"):]
    assert "@media (max-width: 1100px)" in tail, (
        "the 1100px collapse must come AFTER the :has() rules — those are "
        "higher specificity and earlier in the file, so they would win"
    )


def test_there_is_a_fallback_without_has_support():
    css = CSS.read_text(encoding="utf-8")
    assert "@supports not selector(:has(*))" in css
