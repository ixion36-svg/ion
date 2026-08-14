"""v0.79.0 — GRC nav group, the Knowledge Base rename, and filters that the
aggregates actually respect.

**GRC.** Compliance, Maturity, Security posture, Service desk and Audit logs
were scattered across Reporting, Engineering and Administration, so "what do I
show an auditor?" had no single answer. They are one menu now. The thing worth
guarding is that this is a place to FIND them, not a widening: five surfaces,
five different permissions, each still gated, and no GRC menu at all for a user
who holds none of them.

**Filters.** Two separate faults with the same shape — a number on screen that
did not describe what was under it:

  * /cases could not be narrowed by status at all, even though /api/cases has
    always returned open, acknowledged and closed.
  * /alerts computed its stat tiles and Top-N panels from `allAlerts` with the
    comment "so panels always show full picture". Narrow the table to one host
    and Top Hosts still listed every host.

The subtle part of the alerts fix is the split predicate, and
`test_status_tiles_ignore_the_status_filter` is the test most likely to be
"corrected" into a bug by someone tidying up later. The tiles are also the
quick-filter buttons and the page loads on "Open Only" — count them over the
visible rows and Closed reads 0 on arrival, so the control looks dead and you
can never click through to closed alerts.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES = Path("src/ion/web/templates")
STATIC = Path("src/ion/web/static")


@pytest.fixture(scope="module")
def base() -> str:
    return (TEMPLATES / "base.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def app_js() -> str:
    return (STATIC / "js" / "app.js").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def cases() -> str:
    return (TEMPLATES / "cases.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def alerts() -> str:
    return (TEMPLATES / "alerts.html").read_text(encoding="utf-8")


def _inline_js(html: str) -> str:
    return "\n".join(re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S))


def _strip_comments(js: str) -> str:
    """A comment ABOUT a thing is not the thing.

    This suite has now produced this false positive four times — a note
    explaining that Postgres stores 'OPEN' read as the code comparing against
    it. Assert on code, not on prose.
    """
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    return re.sub(r"^\s*//.*$", "", js, flags=re.M)


def _nav(base: str) -> str:
    return base[base.index('<nav id="tw-nav"'):base.index("</nav>")]


# ── GRC nav group ────────────────────────────────────────────────────────


def test_grc_is_a_top_level_nav_group(base):
    nav = _nav(base)
    assert 'id="nav-group-grc"' in nav
    assert ">GRC" in nav


@pytest.mark.parametrize("href,item_id", [
    ("/compliance", "nav-grc-compliance"),
    ("/maturity", "nav-grc-maturity"),
    ("/security", "nav-security-link"),
    ("/change-requests", "nav-grc-servicedesk"),
    ("/audit-logs", "nav-grc-audit"),
])
def test_grc_holds_the_five_surfaces(href, item_id, base):
    grc = base[base.index('id="nav-group-grc"'):]
    grc = grc[:grc.index("</div>\n            </div>") + 10]
    assert f'href="{href}"' in grc, f"{href} is not in the GRC menu"
    assert f'id="{item_id}"' in grc


@pytest.mark.parametrize("href,gone_from", [
    ("/compliance", "Reporting"),
    ("/maturity", "Reporting"),
    ("/audit-logs", "Administration"),
])
def test_moved_items_left_their_old_menu(href, gone_from, base):
    """Listed in two menus is worse than listed in one — the second copy is the
    one nobody updates."""
    nav = _nav(base)
    assert nav.count(f'href="{href}"') == 1, f"{href} appears in more than one menu"


def test_every_grc_item_is_permission_gated(app_js):
    """Five surfaces, five DIFFERENT permissions. Grouping them must not hand
    anyone a link to something they cannot open."""
    block = app_js[app_js.index("const grcItems = ["):]
    block = block[:block.index("];")]
    for perm in ("alert:read", "security:read", "system:settings", "system:audit_view"):
        assert perm in block, f"{perm} is not checked for its GRC item"


def test_grc_menu_disappears_when_every_item_is_hidden(app_js):
    """A user holding none of the five should not see an empty GRC menu."""
    assert "'nav-group-grc'" in app_js
    loop = app_js[app_js.index("['nav-group-engineering'"):]
    loop = loop[:loop.index("});")]
    assert "nav-group-grc" in loop


def test_group_hiding_matches_the_current_nav_markup(app_js):
    """This loop queried .nav-dropdown-menu and <li> — PRE-reskin markup. The
    tw- nav renders .tw-drop-menu with <a> children, so it had quietly stopped
    doing anything at all."""
    loop = app_js[app_js.index("['nav-group-engineering'"):]
    loop = loop[:loop.index("});")]
    assert ".tw-drop-menu" in loop
    assert ".tw-drop-item" in loop


# ── Reference → Knowledge Base ───────────────────────────────────────────


def test_reference_is_renamed_knowledge_base(base):
    nav = _nav(base)
    assert ">Knowledge Base</a>" in nav
    assert ">Reference</a>" not in nav


# ── /cases status filter ─────────────────────────────────────────────────


def test_cases_board_has_a_status_filter(cases):
    assert 'id="filter-status"' in cases
    sel = cases[cases.index('id="filter-status"'):]
    sel = sel[:sel.index("</select>")]
    for value in ("open", "acknowledged", "closed"):
        assert f'value="{value}"' in sel, f"no {value} option"
    assert 'value=""' in sel, "no way back to all statuses"


def test_cases_status_filter_compares_the_serialised_value(cases):
    """Postgres stores the enum NAME ('OPEN') but the API serialises the VALUE
    ('open'). Comparing against the stored name matches nothing."""
    js = _strip_comments(_inline_js(cases))
    fn = js[js.index("function filterCases()"):]
    fn = fn[:fn.index("\n}")]
    assert "c.status !== status" in fn
    assert "'OPEN'" not in fn and '"OPEN"' not in fn


def test_cases_status_filter_is_wired_to_rerender(cases):
    assert 'id="filter-status"' in cases
    sel = cases[cases.index('id="filter-status"'):]
    assert 'data-change-action="filterCases"' in sel[:sel.index(">")]


# ── /alerts: aggregates follow the filter ────────────────────────────────


def test_side_panels_no_longer_pinned_to_all_alerts(alerts):
    js = _inline_js(alerts)
    fn = js[js.index("function renderSidePanels()"):]
    fn = fn[:fn.index("\n}")]
    assert "_aggregationSource()" in fn
    assert "const source = allAlerts;" not in fn, "the panels ignore the filter again"


def test_stat_tiles_no_longer_pinned_to_all_alerts(alerts):
    js = _inline_js(alerts)
    fn = js[js.index("function updateStatsBar()"):]
    fn = fn[:fn.index("\n}")]
    assert "_aggregationSource()" in fn


def test_status_tiles_ignore_the_status_filter(alerts):
    """The Open/Acknowledged/Closed tiles are ALSO the quick-filter buttons,
    and the page loads on "Open Only". Count them over the visible rows and
    Closed shows 0 on arrival — a dead-looking control you can never use to
    reach closed alerts. They read the set that skips the status filter and
    honours every other one."""
    js = _inline_js(alerts)
    fn = js[js.index("function updateStatsBar()"):]
    fn = fn[:fn.index("\n// ") if "\n// " in fn else len(fn)]
    assert "_statusTileSource()" in fn, "status tiles are counting the filtered rows"


def test_the_two_sets_are_built_from_one_predicate_split(alerts):
    js = _inline_js(alerts)
    fn = js[js.index("function applyFilters()"):]
    fn = fn[:fn.index("\n}")]
    # The invariant is the SPLIT, not the exact predicate expression: the first
    # set must apply the non-status filters (v0.81 composes the saved-view
    # predicate in as well) and must not apply the status filter, and the
    # second set must derive from the first via matchesStatus only.
    first = re.search(r"alertsIgnoringStatus = allAlerts\.filter\((.*?)\);", fn)
    assert first, "first set is no longer built from allAlerts.filter(...)"
    assert "matchesNonStatus" in first.group(1)
    assert not re.search(r"(?<!Non)matchesStatus", first.group(1)), \
        "status filter leaked into the set the status tiles count"
    assert "filteredAlerts = alertsIgnoringStatus.filter(matchesStatus)" in fn


def test_filtered_stats_say_they_are_filtered(alerts):
    """A filtered total that looks identical to an estate total misreports the
    estate."""
    assert 'id="stats-filtered-badge"' in alerts
    js = _inline_js(alerts)
    assert "_filtersNarrow()" in js
    assert "of ${allAlerts.length}" in js
