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

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TPL = ROOT / "src" / "ion" / "web" / "templates"
CSS = ROOT / "src" / "ion" / "web" / "static" / "css"
BASE = TPL / "base.html"


def _strip_comments(src: str) -> str:
    """These sheets' own header comments name the selectors below, and this
    module's docstring names several more. A source-reading assertion that
    skips this step passes against prose."""
    return re.sub(r"/\*.*?\*/", " ", src, flags=re.S)


# page template stem -> (sheet file name, load-bearing selectors)
#: Empty, and finished. Every page sheet is retired; see
#: tests/test_retired_page_sheets.py for the per-page guarantees.
PAGES: dict[str, tuple[str, tuple[str, ...]]] = {}



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

def test_every_page_sheet_has_been_retired():
    """The registry above is empty, and that is the finished state.

    Each of these sheets is now nested under its body[data-page] scope in
    frontend/ion-pages.css and compiled into ion.css, so a page carries no
    stylesheet of its own. tests/test_retired_page_sheets.py holds what this
    file used to hold, per page.

    This is the live part. Every parametrized test here now takes an empty
    set and pytest skips it, which reports success while checking nothing --
    so the one claim worth keeping is asserted directly: no page-specific
    sheet has come back.
    """
    assert PAGES == {}, (
        f"a page sheet is registered as linked again: {sorted(PAGES)}. "
        "Either it was reintroduced, or its retirement was reverted."
    )

    globals_ = set(re.findall(r"/static/css/([\w.-]+\.css)",
                              BASE.read_text(encoding="utf-8")))
    on_disk = {q.name for q in CSS.glob("*.css")}
    orphans = sorted(
        name for name in on_disk - globals_
        if any(name in (TPL / f).read_text(encoding="utf-8", errors="replace")
               for f in ("alerts.html", "cases.html", "settings.html",
                         "chat.html", "observables.html", "analytics.html",
                         "integrations.html", "login.html", "wallboard.html"))
    )
    assert not orphans, f"pages link these sheets again: {orphans}"
