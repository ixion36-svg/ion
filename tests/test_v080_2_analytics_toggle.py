"""v0.80.1 — the Analytics Dashboard button works on the first click.

The drawer on /alerts is hidden by a CSS CLASS — `._ion-s-c8be1ccba6 {display:none}`,
produced by the v0.31.21 inline-style migration. Every check in the page read
`el.style.display`, which returns the **inline** style and is therefore `''`
until something assigns it.

Two live consequences:

1. **The toggle needed two clicks to open.** First click: `'' !== 'none'`, so it
   took the "currently open, close it" branch, wrote `display:none` — no visible
   change — and only the second click opened the drawer. A button that does
   nothing the first time you press it reads as broken, which is the likely
   reason nobody reported the analytics panels being in the way.

2. **Three guards were inverted while hidden.** `renderKeyMetrics`,
   `renderTriageStatusDonut` and `renderMitreHeatmap` were gated on
   `style.display !== 'none'`, which evaluated TRUE on a collapsed drawer — so
   they redrew charts nobody could see on every triage update.

`getComputedStyle` asks the honest question — is this element actually visible —
regardless of whether a class or an inline style hid it.

This is the same defect family as the v0.79.5 ReferenceError and the v0.80.0
inline styles: **the failure is silent.** No error, no log, no exception; just a
control that appears inert and work done for nothing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ALERTS = Path("src/ion/web/templates/alerts.html")
MIGRATED = Path("src/ion/web/static/css/ion-migrated-styles.css")

DRAWER_ID = "analytics-dashboard"
HIDING_CLASS = "_ion-s-c8be1ccba6"


def _strip(src: str) -> str:
    src = re.sub(r"<!--.*?-->", "", src, flags=re.S)
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"^\s*//.*$", "", src, flags=re.M)


@pytest.fixture(scope="module")
def page() -> str:
    return _strip(ALERTS.read_text(encoding="utf-8"))


def test_the_drawer_is_still_hidden_by_a_class_not_an_inline_style(page):
    """The whole bug rests on this. If the hiding ever moves to an inline
    style the reasoning changes, and this test should be revisited rather than
    silently kept passing."""
    assert HIDING_CLASS in page, "drawer no longer carries the hashed hiding class"
    css = MIGRATED.read_text(encoding="utf-8")
    rule = re.search(re.escape(HIDING_CLASS) + r"\s*\{[^}]*\}", css)
    assert rule and "display:none" in rule.group(0).replace(" ", ""), (
        "the hiding class no longer sets display:none"
    )


def test_visibility_is_never_read_from_the_inline_style(page):
    """`el.style.display` cannot see a class-applied rule. Reading it is the
    bug, wherever it appears."""
    hits = re.findall(
        r"getElementById\(['\"]" + DRAWER_ID + r"['\"]\)\s*\.style\.display", page
    )
    assert not hits, (
        f"{len(hits)} check(s) read the drawer's INLINE style. That is '' on "
        "load even though the class hides it — the toggle then needs two "
        "clicks and the render guards fire while collapsed. Use analyticsIsOpen()."
    )


def test_there_is_one_helper_and_it_asks_the_computed_question(page):
    assert "function analyticsIsOpen(" in page
    fn = page[page.index("function analyticsIsOpen("):]
    fn = fn[:fn.index("\nfunction toggleAnalytics(")]
    assert "getComputedStyle" in fn, (
        "only the computed style reflects a class-applied display:none"
    )


def test_the_toggle_opens_on_the_first_click(page):
    """Opening must be driven by actual visibility, not by the inline value."""
    fn = page[page.index("function toggleAnalytics("):]
    fn = fn[:fn.index("\n}")]
    assert "if (!analyticsIsOpen())" in fn, "open/close branch still keys off the wrong state"
    assert "dash.style.display = 'block'" in fn
    assert "dash.style.display = 'none'" in fn


def test_every_render_guard_uses_the_helper(page):
    """These were the inverted ones — true while hidden, so they redrew
    invisible charts on every triage update."""
    for fn_name in ("renderKeyMetrics();", "renderMitreHeatmap();"):
        i = page.index(fn_name)
        window = page[max(0, i - 200):i]
        assert "analyticsIsOpen()" in window, f"{fn_name} is not gated on real visibility"

    fn = page[page.index("function renderAnalytics("):]
    fn = fn[:fn.index("\n    render")]
    assert "if (!analyticsIsOpen()) return;" in fn


def test_the_fix_stays_csp_safe(page):
    """Writing el.style.display is CSSOM and allowed; an inline style= attribute
    is not (style-src-attr 'none'). Guarded by test_v080_csp_inline_styles too,
    but stated here because this fix is the obvious place to reintroduce one."""
    fn = page[page.index("function toggleAnalytics("):]
    fn = fn[:fn.index("\n}")]
    assert 'style="' not in fn
