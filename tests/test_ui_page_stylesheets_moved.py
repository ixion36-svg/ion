"""The seven pages whose inline <style> block became a real stylesheet.

gitlab, templates, template_view, security_dashboard, scheduler,
alert_arkime and wallboard each carried their whole appearance in a
`<style nonce="...">` block. On 2026-10-13 each block moved out to
`static/css/<page>-page.css`, verbatim, and the page links it instead.

Four things about that move break silently, which is what each test here
is for.

**The sheet can simply not load.** A page whose rules have left the
template and whose `<link>` is misspelt, missing, or in a block base.html
does not render renders completely unstyled, and no other test in the
repo looks at it: the status tool is happy (there is no inline block), the
state-class check is happy (the rules exist in a file it reads), and the
route tests never fetch CSS.

**The cascade can invert.** Every one of these blocks sat in
`{% block scripts %}`, at the very end of <body>. It therefore loaded
after every linked sheet, and won `!important`-free ties against daisyUI
by source order alone -- `.modal.active`, `#sch-modal-bg.show` and
gitlab's `.loading` are each a bridge that only works because of that.
`{% block head_css %}` is base.html line 50, after ion.css,
ion-migrated-styles.css and alert-detail.css but *before*
ion-workspace.css and ion-shell.css. ion-shell.css is the two blocks
that used to sit in base.html's body. So the move is only safe while
those sheets share no selector with these pages, and while base.html
keeps head_css below the sheets these rules beat.

**A rule can be dropped in transit.** `tests/test_ui_state_classes_have_rules.py`
catches a class that JS toggles and nothing paints, but it cannot catch a
rule for a class that only the server emits -- `.doc-type-SOP`,
`.severity-critical`, `.issue-state.opened`. Those come from a Jinja
fragment, so no `classList.add` mentions them. The selectors pinned below
are the load-bearing ones: a modal bridge, a state colour, a layout the
page cannot do without.

**The `light` column stops watching.** `tools/ui_redesign_status.py`
measures light-on-dark colour only inside a template's inline `<style>`.
The instant the rules leave the template the measure returns yes for free,
so the guarantee has to be re-asserted against the sheets themselves --
which is `test_the_moved_sheets_have_no_light_colour_without_a_fill`
below. gitlab's `.issue-label` was the one real violation: `color: white`
with the background arriving at runtime from data-ion-style.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TPL = ROOT / "src" / "ion" / "web" / "templates"
CSS = ROOT / "src" / "ion" / "web" / "static" / "css"
BASE = TPL / "base.html"

#: Linked by base.html BEFORE {% block head_css %}, so a moved sheet still
#: beats them on source order exactly as the inline block did. If head_css
#: ever moves above one of these, every bridge rule in these sheets loses.
BEATEN_BY_HEAD_CSS = ("ion.css", "ion-migrated-styles.css", "alert-detail.css")

#: Linked by base.html AFTER {% block head_css %}. The page sheets used to
#: beat these from an in-body block and now do not, which is only safe
#: while no selector is shared. ion-shell.css is base.html's two blocks,
#: linked after ion-workspace. Measured empty on 2026-10-13 for all seven.
LOADS_AFTER_HEAD_CSS = ("ion-workspace.css", "ion-shell.css")


def _strip_comments(src: str) -> str:
    """These sheets' own header comments name the selectors below, and this
    module's docstring names several more. A source-reading assertion that
    skips this step passes against prose."""
    return re.sub(r"/\*.*?\*/", " ", src, flags=re.S)


# page template stem -> (sheet file name, load-bearing selectors)
PAGES: dict[str, tuple[str, tuple[str, ...]]] = {
    "gitlab": (
        "gitlab-page.css",
        (
            '#create-issue-modal[style*="flex"]',   # modal bridge: JS sets display:flex
            ".connection-status.connected",          # banner state from the fragment
            "#issues-list .loading",                 # the word, not daisyUI's spinner
            ".issue-card",
            ".issue-state.opened",
            ".issue-label",
            "#issue-labels",                         # native multi-select, not .select
        ),
    ),
    "templates": (
        "templates-page.css",
        (
            "#folders-modal.modal",                  # modal bridge: JS sets display:flex
            ".folder-item.active",
            "#templates-list > .card",
            "#templates-list .tag",
        ),
    ),
    "template_view": (
        "template-view-page.css",
        (
            ".tabs-border > .tab.content-tab-btn.active",   # .active, not .tab-active
            "#version-modal.modal",
            ".sv-card",
            ".checkpoint-badge",                     # beats the compiled neon gradient
            ".diff-view .diff-add",
        ),
    ),
    # security_dashboard is deliberately absent. It no longer links a sheet:
    # its badges moved to ion-value-scales.css and the rest to ion-pages.css,
    # both compiled into ion.css. The guarantees this registry gave it are
    # re-asserted in tests/test_security_dashboard_scales.py.
    # scheduler and alert_arkime are deliberately absent, like
    # security_dashboard: their rules moved into frontend/ion-pages.css and
    # they link no sheet. tests/test_retired_page_sheets.py holds what this
    # registry held for them.
    "wallboard": (
        "wallboard-page.css",
        (
            ".ion-tw-page",                          # undo the 56px nav subtraction
            "::-webkit-scrollbar",
            "#wb-attention",
            ".wb-att-critical",
            ".wb-panel-critical",
            "@keyframes wb-att-flash",
        ),
    ),
}

#: wallboard.html does not extend base.html, so it has no head_css block and
#: its own <head> carries the link.
STANDALONE = {"wallboard"}


def _page(stem: str) -> str:
    return (TPL / f"{stem}.html").read_text(encoding="utf-8")


def _sheet(stem: str) -> str:
    return (CSS / PAGES[stem][0]).read_text(encoding="utf-8")


def _selectors(css: str) -> set[str]:
    """Normalised selectors, at-rules excluded, comments already gone."""
    out: set[str] = set()
    for m in re.finditer(r"([^{}]+)\{", _strip_comments(css)):
        for sel in m.group(1).split(","):
            sel = " ".join(sel.split())
            if sel and not sel.startswith("@") and not sel.endswith(":"):
                out.add(sel)
    return out


@pytest.mark.parametrize("stem", sorted(PAGES))
def test_the_page_has_no_inline_style_block_left(stem):
    """The `styled` column of tools/ui_redesign_status.py, asserted per page
    so a failure names the page rather than a total."""
    assert "<style" not in _page(stem), f"{stem}.html still carries a <style> block"


@pytest.mark.parametrize("stem", sorted(PAGES))
def test_the_page_links_its_own_sheet(stem):
    sheet = PAGES[stem][0]
    assert (CSS / sheet).is_file(), f"{sheet} does not exist"
    expected = f'<link rel="stylesheet" href="/static/css/{sheet}?v={{{{ ion_version }}}}">'
    assert expected in _page(stem), f"{stem}.html does not link {sheet}"


@pytest.mark.parametrize("stem", sorted(PAGES))
def test_the_link_sits_where_it_still_beats_the_sheets_it_used_to_beat(stem):
    """The inline block loaded last. A link that lands above ion.css loses
    every daisyUI bridge in the sheet, and nothing else here would notice.

    Both halves, because the page and base.html can each break it: the page
    by linking its sheet outside head_css, base.html by moving head_css
    above a sheet these rules override."""
    sheet = PAGES[stem][0]
    page = _strip_comments(_page(stem))
    if stem in STANDALONE:
        at = page.index(sheet)
        for earlier in ("ion.css", "ion-migrated-styles.css"):
            assert page.index(earlier) < at, (
                f"{stem}.html links {sheet} before {earlier}"
            )
        return
    block = re.search(r"\{%\s*block head_css\s*%\}(.*?)\{%\s*endblock\s*%\}", page, re.S)
    assert block, f"{stem}.html has no head_css block"
    assert sheet in block.group(1), f"{sheet} is linked outside {stem}.html's head_css"

    base = _strip_comments(BASE.read_text(encoding="utf-8"))
    at = base.index("{% block head_css %}")
    for earlier in BEATEN_BY_HEAD_CSS:
        assert base.index(earlier) < at, (
            f"head_css renders before {earlier}, so {sheet} no longer beats it"
        )
    for later in LOADS_AFTER_HEAD_CSS:
        assert base.index(later) > at, (
            f"{later} moved above head_css; the collision check "
            "below is measuring the wrong direction"
        )


@pytest.mark.parametrize("stem", sorted(PAGES))
def test_the_sheet_still_carries_the_load_bearing_selectors(stem):
    """A rule dropped while moving 650 lines of CSS between files. The
    server-emitted state classes are the ones no other check can see."""
    css = _strip_comments(_sheet(stem))
    missing = [s for s in PAGES[stem][1] if s not in css]
    assert not missing, f"{PAGES[stem][0]} lost: {missing}"


@pytest.mark.parametrize("stem", sorted(PAGES))
def test_the_sheet_shares_no_selector_with_the_sheet_that_now_outranks_it(stem):
    """Sheets linked after head_css win equal-specificity ties these rules
    used to win from the end of the body. Harmless only while nothing is shared."""
    page_sels = _selectors(_sheet(stem))
    for name in LOADS_AFTER_HEAD_CSS:
        shared = page_sels & _selectors((CSS / name).read_text(encoding="utf-8"))
        assert not shared, (
            f"{PAGES[stem][0]} shares selectors with {name}, which "
            f"now wins the tie it used to lose: {sorted(shared)}"
        )


@pytest.mark.parametrize("stem", sorted(PAGES))
def test_the_sheet_is_page_scoped(stem):
    """base.html loads a dozen sheets on every page whether used or not; a
    sheet one route needs belongs in that route's head_css.

    The first assertion is what stops this passing vacuously: "no OTHER
    template links it" is true of a sheet nothing links at all."""
    sheet = PAGES[stem][0]
    assert sheet in _page(stem), f"{stem}.html does not link {sheet}"
    others = [
        f.relative_to(TPL).as_posix()
        for f in sorted(TPL.rglob("*.html"))
        if f.name != f"{stem}.html" and sheet in f.read_text(encoding="utf-8")
    ]
    assert not others, f"{sheet} is also linked by {others}"


@pytest.mark.parametrize("stem", sorted(PAGES))
def test_the_moved_sheets_have_no_light_colour_without_a_fill(stem):
    """The `light` column measures a template's inline <style> and nothing
    else, so it returns yes for free the moment the rules move out. Re-assert
    it against the sheet, with the tool's own measure rather than a second
    opinion: a rule setting colour and background together flips as a pair,
    and only colour-without-fill goes invisible on the light page.

    gitlab's `.issue-label` was the one real violation of the seven."""
    spec = importlib.util.spec_from_file_location(
        "_ui_redesign_status", ROOT / "tools" / "ui_redesign_status.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    bad = mod._invisible_light_rules(_sheet(stem))
    assert not bad, f"{PAGES[stem][0]} has light colour with no fill: {bad}"
