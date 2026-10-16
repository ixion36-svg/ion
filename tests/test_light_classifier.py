"""The light-mode classifier must not count text that has its own fill.

tools/ui_redesign_status.py's `light` column decides which templates still
need light-mode work, and the first version counted every `color: #fff` in a
template's inline <style>. Measured 2026-10-12 that was **133 literals across
24 templates**. The corrected classifier reports **13 across 9**, because 120
of them were rules like

    .notification-success { background: var(--success); color: white; }

which are correct: white on a coloured fill. Rewriting those the same way as
`.np-note-title { color: #fff }`, which sits on the page and is invisible in
light mode, breaks the first to fix the second. The generated document warns
about exactly this trap one table lower, for CSS deletion, and the measuring
tool was falling into it.

The rule the classifier encodes: a block that sets colour AND a background
moves both halves together under a theme flip, or neither. A block that sets
only colour is text against whatever the page provides. Only the second can
go invisible.

This is a grep, so it has a ceiling: a rule whose background comes from a
different rule or from runtime style still reads as a false positive here.
tools/contrast_crawl.py renders and measures the composited result and is the
authoritative instrument. This one keeps the work list honest enough to act on.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from ui_redesign_status import _invisible_light_rules  # noqa: E402


@pytest.mark.parametrize("css,expected,why", [
    (".a { background: var(--success); color: white; }", 0,
     "a var() background is still a background: both halves flip together"),
    (".b { background: #f85149; color: white }", 0, "hex fill"),
    (".c { background-color: rgb(20,20,20); color:#fff }", 0, "rgb fill"),
    (".d { background-image: linear-gradient(#000,#111); color:#fff }", 0,
     "a gradient is a fill too"),
    (".e { color: #fff; font-weight: 600 }", 1, "no fill: invisible on a light page"),
    (".f { color: #ffffff }", 1, "six-digit form"),
    (".g { color: white }", 1, "named form"),
    (".h { color: rgba(255, 255, 255, 0.8) }", 1, "rgba form"),
    (".i { background: transparent; color:#fff }", 1,
     "transparent is not a fill"),
    (".j { background: none; color:#fff }", 1, "nor is none"),
])
def test_a_rule_is_counted_only_when_it_has_no_fill(css, expected, why):
    assert len(_invisible_light_rules(css)) == expected, why


def test_a_commented_out_rule_is_not_a_rule():
    css = "/* .old { color:#fff } */ .new { background:#000; color:#fff }"
    assert _invisible_light_rules(css) == []


def test_a_property_ending_in_color_is_not_the_color_property():
    """`border-color: #fff` is decoration at a 3:1 floor, not body text, and
    `-webkit-text-fill-color` is not `color` either."""
    assert _invisible_light_rules(".a { border-color: #fff }") == []
    assert _invisible_light_rules(".b { background-color: #fff }") == []


def test_the_selector_is_reported_so_the_work_list_is_actionable():
    (sel,) = _invisible_light_rules(".np-note-title, .x > .y { color:#fff }")
    assert "np-note-title" in sel


def test_several_rules_in_one_sheet_are_counted_independently():
    css = """
    .ok   { background: var(--c); color: #fff }
    .bad1 { color: #fff }
    .bad2 { color: white; padding: 4px }
    """
    found = _invisible_light_rules(css)
    assert len(found) == 2
    assert not any("ok" in f for f in found)


# ---------------------------------------------------------------------------
# The control: the old behaviour really did over-count
# ---------------------------------------------------------------------------


def test_the_sheet_the_old_classifier_got_wrong():
    """Four real toast rules from alerts.html. The old regex counted all four.

    If this ever counts above zero, the classifier has regressed to grepping
    and the next sweep will break working rules again.
    """
    css = """
    .notification-success { background: var(--success); color: white; }
    .notification-error   { background: var(--danger);  color: white; }
    .notification-warning { background: var(--warning); color: white; }
    .notification-info    { background: var(--info);    color: white; }
    """
    assert _invisible_light_rules(css) == []


def test_the_live_templates_report_a_tractable_number():
    """A sanity bound, not a pin on the exact count, which falls as the sweep
    lands. Above 40 means the classifier is over-counting again; the measured
    figure when this was written was 13.
    """
    from ui_redesign_status import measure

    templates = ROOT / "src" / "ion" / "web" / "templates"
    total = sum(measure(p)["light"] for p in templates.glob("*.html"))
    assert total <= 40, (
        f"{total} invisible rules reported; the classifier is counting "
        f"text-on-fill again"
    )
