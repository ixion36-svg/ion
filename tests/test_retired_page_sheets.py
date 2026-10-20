"""Pages that no longer link a stylesheet of their own.

`tests/test_ui_page_stylesheets_moved.py` guards the pages that still have
one. As each is retired its entry leaves that registry and arrives here, so
the two together always account for every page: a page in neither is a page
nobody is checking.

The failure this file exists for is specific to the destination. A rule in
`frontend/ion-pages.css` is scoped `body[data-page="<id>"]`, and the scope
comes from `{% block page_id %}` in the template. Those two are written in
different files, nothing links them, and if they disagree the selector
matches nothing -- the page still renders, just unstyled in that one
respect, which is the quietest way this project has broken itself before.

The rules are asserted against the authored source rather than the shipped
`ion.css`, because the build minifies the selectors; `test_tailwind_build_pin`
is what proves the shipped sheet was built from this source.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TPL = ROOT / "src/ion/web/templates"
CSS = ROOT / "src/ion/web/static/css"
PAGES_CSS = ROOT / "frontend/ion-pages.css"

#: page_id -> (template stem, the sheet it used to link, load-bearing
#: selectors carried over verbatim from that sheet's registry entry)
RETIRED = {
    "security_dashboard": (
        "security_dashboard",
        "security-dashboard-page.css",
        (
            ".modal.active",                       # modal bridge: JS toggles .active
            "#events-table th",
            ".matched-content code",
        ),
    ),
    "maturity": (
        "maturity",
        "maturity-page.css",
        (".mat-title",),                           # beats daisyUI .input on specificity
    ),
    "data_flow": (
        "data_flow",
        "data-flow-page.css",
        (".df-winlog-row .df-event-id",),          # ties with .val, wins on order
    ),
    "scheduler": (
        "scheduler",
        "scheduler-page.css",
        (
            "#sch-modal-bg.show",                  # modal bridge: JS toggles .show
            "#sch-exec-bg.show",
            ".sch-card.ok",
            ".sch-grid",                           # auto-fit grid, no daisyUI token
        ),
    ),
    "alert_arkime": (
        "alert_arkime",
        "alert-arkime-page.css",
        (
            ".arkime-commit .mode-new",            # the radio that drives the switch
            ".arkime-commit .mode-bar label",
            ".arkime-commit .mode-new:checked ~ .commit-fields .commit-existing",
        ),
    ),
    "templates": (
        "templates",
        "templates-page.css",
        (
            "#folders-modal.modal",                # modal bridge: JS sets display:flex
            ".folder-item.active",
            "#templates-list > .card",
            "#templates-list .tag",
        ),
    ),
    "template_view": (
        "template_view",
        "template-view-page.css",
        (
            ".tabs-border > .tab.content-tab-btn.active",  # .active, not .tab-active
            "#version-modal.modal",
            ".sv-card",
            ".checkpoint-badge",
            ".diff-view .diff-add",
        ),
    ),
    "documents": (
        "documents",
        "documents-page.css",
        (
            ".doc-row",
            ".doc-row-archived",
            ".doc-unmeasured",                     # a figure the payload lacked
            ".doc-filter-notice",                  # a filter that could not be honoured
        ),
    ),
}


def _page(stem: str) -> str:
    return (TPL / f"{stem}.html").read_text(encoding="utf-8")


def _pages_css() -> str:
    return re.sub(r"/\*.*?\*/", "", PAGES_CSS.read_text(encoding="utf-8"), flags=re.S)


def _scope_block(css: str, page_id: str) -> str:
    """The body of a `body[data-page="x"] { ... }` wrapper, or "".

    A sheet moved verbatim is nested inside one of these and the build
    flattens it; a sheet moved rule by rule is prefixed instead. Both forms
    are in this file, so the selector check has to know about both.
    """
    opener = f'body[data-page="{page_id}"] {{'
    start = css.find(opener)
    if start == -1:
        return ""
    i = start + len(opener)
    depth = 1
    while i < len(css) and depth:
        if css[i] == "{":
            depth += 1
        elif css[i] == "}":
            depth -= 1
        i += 1
    return css[start + len(opener):i - 1]


@pytest.mark.parametrize("page_id", sorted(RETIRED))
def test_the_old_sheet_is_gone(page_id):
    _, sheet, _ = RETIRED[page_id]
    assert not (CSS / sheet).exists(), f"{sheet} is back"


@pytest.mark.parametrize("page_id", sorted(RETIRED))
def test_the_page_links_no_stylesheet_of_its_own(page_id):
    stem, sheet, _ = RETIRED[page_id]
    page = _page(stem)
    assert sheet not in page
    assert "{% block head_css %}" not in page, (
        "an empty head_css block says the page has a sheet when it does not"
    )


@pytest.mark.parametrize("page_id", sorted(RETIRED))
def test_the_template_declares_the_scope_its_rules_are_written_against(page_id):
    """The scope and the selector live in different files. If they disagree
    the rules match nothing and the page renders unstyled without an error."""
    stem = RETIRED[page_id][0]
    assert f"{{% block page_id %}}{page_id}{{% endblock %}}" in _page(stem), (
        f"{stem}.html does not declare page_id {page_id!r}, so every "
        f'body[data-page="{page_id}"] rule in ion-pages.css is dead'
    )


@pytest.mark.parametrize("page_id,selector", [
    (pid, sel) for pid, (_, _, sels) in sorted(RETIRED.items()) for sel in sels
])
def test_each_load_bearing_rule_survived_the_move(page_id, selector):
    css = _pages_css()
    prefixed = f'body[data-page="{page_id}"] {selector}' in css
    nested = selector in _scope_block(css, page_id)
    assert prefixed or nested, (
        f"{selector} is not scoped to {page_id} in ion-pages.css, in either "
        "the prefixed or the nested form. It was pinned because only the "
        "server emits it, so no state-class or dead-CSS check would notice "
        "it going missing."
    )


def test_a_retired_sheet_never_reappears_in_the_other_registry():
    """The two registries are disjoint by construction. A page in both would
    be asserted to link a sheet and to have none, and whichever test ran
    second would be the one believed.

    This does not claim every page sheet on disk is registered: that registry
    covers only the seven whose inline <style> block moved out in October,
    and fourteen older sheets predate it.
    """
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_ui_page_stylesheets_moved import PAGES as STILL_LINKED

    overlap = set(RETIRED) & set(STILL_LINKED)
    assert not overlap, f"registered as both linked and retired: {sorted(overlap)}"

    for page_id, (_, sheet, _) in RETIRED.items():
        assert sheet not in {s for s, _ in STILL_LINKED.values()}, (
            f"{sheet} is retired but still listed as linked"
        )
