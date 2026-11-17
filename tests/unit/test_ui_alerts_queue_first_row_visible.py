"""The queue's column header must not sit on top of the first body row.

`.aq-wrap` scrolls sideways, which makes it the scroll container its sticky
`th` cells are offset against. A `top` measured from the page chrome therefore
pushes the header down inside the wrapper by that much, over the first row:
the first group's bar and its "Select all" when grouped, the first alert when
not. The row is in the DOM and nothing errors, so only laying the real
stylesheet out in a browser shows it.
"""
from __future__ import annotations

import pathlib

import pytest

CSS = pathlib.Path(__file__).resolve().parents[2] / (
    "src/ion/web/static/css/alerts-queue.css")

NAV_PX = 33

# The row shapes alerts-queue.js render() emits, under a nav the height the
# page measured into --aq-stick.
HARNESS = """<!doctype html><html><head><style>
:root {{ --aq-stick: {nav}px; }}
body {{ margin: 0; }}
nav {{ height: {nav}px; }}
{css}
</style></head><body>
<nav class="tw-nav"></nav>
<div class="aq-wrap"><table class="aq {density}" id="alerts-table">
<thead><tr><th class="aq-chk"><input type="checkbox"></th><th>Title</th></tr></thead>
<tbody>{first}
<tr class="aq-row"><td class="aq-chk"><input type="checkbox"></td><td>alert b</td></tr>
</tbody></table></div>
</body></html>"""

GROUP_ROW = (
    '<tr class="aq-grp" data-aq-g="critical"><td colspan="2">'
    '<div class="aq-ghead sev-critical"><span class="aq-gn">critical</span>'
    '<button class="aq-gsel" id="probe">Select all</button></div></td></tr>')
ALERT_ROW = (
    '<tr class="aq-row"><td class="aq-chk"><input type="checkbox" id="probe">'
    '</td><td>alert a</td></tr>')

PROBE = """() => {
  const th = document.querySelector('thead th').getBoundingClientRect();
  const row = document.querySelector('tbody tr').getBoundingClientRect();
  const p = document.getElementById('probe');
  const b = p.getBoundingClientRect();
  const hit = document.elementFromPoint(b.left + b.width / 2, b.top + b.height / 2);
  return { headerBottom: th.bottom, rowTop: row.top, reachable: hit === p };
}"""


@pytest.fixture(scope="module")
def layout_browser():
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except sync_api.Error as exc:
            pytest.skip(f"no chromium for playwright: {exc}")
        yield b
        b.close()


@pytest.mark.parametrize("density", ["", "aq-roomy"])
@pytest.mark.parametrize("first", [GROUP_ROW, ALERT_ROW], ids=["grouped", "ungrouped"])
def test_the_first_body_row_is_clear_of_the_column_header(layout_browser, first, density):
    page = layout_browser.new_page(viewport={"width": 1440, "height": 900})
    try:
        page.set_content(HARNESS.format(
            nav=NAV_PX, css=CSS.read_text(encoding="utf-8"),
            density=density, first=first))
        got = page.evaluate(PROBE)
    finally:
        page.close()
    assert got["headerBottom"] <= got["rowTop"], (
        f"the column header overlaps the first row by "
        f"{got['headerBottom'] - got['rowTop']}px")
    assert got["reachable"], "a click on the first row's control lands on the header"
