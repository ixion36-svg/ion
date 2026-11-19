"""The alerts bulk bar marks verdicts the way the case window does.

Its three buttons send each selected alert to POST /alerts/{id}/close with
close_case false. With the endpoint's default (true) one click would close
every case the selection touches, and every other alert in those cases.
The Columns menu and the sticky header are drawn on a solid surface: the
glass themes' --ion-surface-2 is 7% white and the table showed through.
"""

import re
from pathlib import Path

WEB = Path(__file__).resolve().parents[1] / "src/ion/web"
PAGE = (WEB / "templates/alerts.html").read_text(encoding="utf-8")
CSS = (WEB / "static/css/alerts-queue.css").read_text(encoding="utf-8")


def _bulk_verdict_js() -> str:
    start = PAGE.index("async function bulkVerdict(")
    return PAGE[start:PAGE.index("\n}\n", start)]


def test_the_bar_offers_the_three_case_window_verdicts():
    bar = PAGE[PAGE.index('id="bulk-actions-toolbar"'):]
    bar = bar[:bar.index("<!-- Alert Context Menu -->")]
    sent = re.findall(r'data-click-action="bulkVerdict" data-args=\'\["(\w+)"\]\'', bar)
    assert sent == ["escalated", "benign", "false_positive"]


def test_marking_never_closes_the_case():
    js = _bulk_verdict_js()
    assert "/close'" in js
    assert "close_case: false" in js
    assert "close_case: true" not in js


def _rule(selector: str) -> str:
    start = CSS.index(selector + " {")
    return CSS[start:CSS.index("}", start)]


def test_the_columns_menu_and_sticky_header_are_opaque():
    for selector in (".aq-colmenu", "table.aq th"):
        assert "background: var(--bg-elevated" in _rule(selector), selector
