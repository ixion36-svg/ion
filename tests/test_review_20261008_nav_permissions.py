"""Navigation gated by the authoritative permission map (review §23, stage 5).

The review credits ION with "permission-sensitive visibility", and that is
true of about a fifth of the navigation. The header carries 57 links. Twelve
of them are hidden by a hand-written list of element ids in ``app.js``::

    const grcItems = [
        ['nav-grc-compliance',  perms.has('alert:read')],
        ['nav-grc-servicedesk', perms.has('system:settings')],
        ...
    ];

while the permission each page actually requires lives in ``_PAGES`` in
``server.py``, which is what the route enforces. Two lists, maintained by
hand, in different languages, that have to agree. They do not: a link added
without an id and without a matching entry in the JS shows to everyone and
hands them a 403.

The routes were never unsafe — they enforce regardless of what the menu
shows — so this is a usability and trust defect rather than a security one.
It is still worth fixing: a menu full of links that fail is a menu people
stop reading.

The fix is to stop maintaining the second list. ``page_permission_map()``
reads the permissions off the registered routes, and the client hides any
nav link whose target needs a permission the user lacks. The tests below are
mostly about the thing that makes that safe: the map has to be *derived*,
and every gated link has to be covered by it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ion.web.nav_permissions import (
    EXEMPT_PATHS,
    page_permission_map,
    visible_nav_paths,
)

_BASE = _SRC / "ion" / "web" / "templates" / "base.html"


def _nav_hrefs() -> list[str]:
    """Every internal nav href in the header, Jinja conditionals and all."""
    html = _BASE.read_text(encoding="utf-8")
    hrefs = re.findall(r'<a href="(/[^"#?]*)"[^>]*class="tw-(?:nav-link|drop-item)',
                       html)
    return sorted(set(hrefs))


@pytest.fixture(scope="module")
def nav_hrefs():
    return _nav_hrefs()


@pytest.fixture(scope="module")
def perm_map():
    return page_permission_map()


# ── The map is derived, not written down ─────────────────────────────────


class TestDerivation:
    def test_the_map_is_not_empty(self, perm_map):
        assert len(perm_map) > 20

    def test_the_map_agrees_with_the_page_registry(self, perm_map):
        """The authoritative source. If these ever disagree, the menu is
        lying about one of them."""
        from ion.web.server import _PAGES

        for path, _template, permission in _PAGES:
            assert perm_map.get(path) == permission, path

    def test_a_known_page_maps_to_its_known_permission(self, perm_map):
        assert perm_map["/settings"] == "system:settings"
        assert perm_map["/forensics"] == "forensic:read"

    def test_paths_are_absolute_and_unslashed(self, perm_map):
        for path in perm_map:
            assert path.startswith("/")
            assert path == "/" or not path.endswith("/")

    def test_the_map_is_stable_across_calls(self, perm_map):
        assert page_permission_map() == perm_map


# ── Coverage: every nav link is accounted for ────────────────────────────


class TestCoverage:
    def test_the_header_actually_has_the_links_this_tests(self, nav_hrefs):
        """Guards the regex: if the markup changes shape and this finds
        nothing, every other test here would pass vacuously."""
        assert len(nav_hrefs) > 40

    def test_every_nav_link_is_mapped_or_explicitly_exempt(
        self, nav_hrefs, perm_map
    ):
        """The defect: a link that is in neither list shows to everyone and
        then 403s."""
        unaccounted = [
            href for href in nav_hrefs
            if href not in perm_map and href not in EXEMPT_PATHS
        ]
        assert not unaccounted, (
            "these header links have no known permission and are not listed "
            f"as open to any signed-in user: {unaccounted}. Add the page to "
            "the registry, or to EXEMPT_PATHS with a reason."
        )

    def test_the_exempt_list_is_not_a_dumping_ground(self, nav_hrefs):
        """An exemption per link would make the check meaningless."""
        assert len(EXEMPT_PATHS) < len(nav_hrefs) / 2

    def test_nothing_is_both_mapped_and_exempt(self, perm_map):
        """Ambiguity here means two answers to "can they see this"."""
        overlap = sorted(set(perm_map) & set(EXEMPT_PATHS))
        assert not overlap, overlap


# ── Filtering for a role ─────────────────────────────────────────────────


class TestVisibility:
    def test_a_user_with_no_permissions_sees_only_exempt_paths(self):
        visible = visible_nav_paths(set())
        assert set(visible) == set(EXEMPT_PATHS)

    def test_an_analyst_sees_the_alert_surfaces(self):
        visible = set(visible_nav_paths({"alert:read"}))
        assert "/alerts" in visible
        assert "/discover" in visible

    def test_an_analyst_does_not_see_settings(self):
        assert "/settings" not in visible_nav_paths({"alert:read"})

    def test_an_analyst_does_not_see_forensics(self):
        assert "/forensics" not in visible_nav_paths({"alert:read"})

    def test_a_forensic_analyst_sees_forensics(self):
        assert "/forensics" in visible_nav_paths({"alert:read", "forensic:read"})

    def test_holding_every_permission_shows_everything_mapped(self, perm_map):
        every = set(perm_map.values())
        visible = set(visible_nav_paths(every))
        assert set(perm_map) <= visible

    def test_exempt_paths_are_always_visible(self):
        for permissions in (set(), {"alert:read"}, {"system:settings"}):
            visible = set(visible_nav_paths(permissions))
            assert set(EXEMPT_PATHS) <= visible

    def test_an_unknown_permission_does_not_unlock_anything(self):
        assert set(visible_nav_paths({"not:a:permission"})) == set(EXEMPT_PATHS)


# ── Wiring ───────────────────────────────────────────────────────────────


class TestWiring:
    def test_the_endpoint_exists(self):
        src = (_SRC / "ion" / "web" / "server.py").read_text(encoding="utf-8")
        assert "/api/nav/permissions" in src

    def test_the_client_hides_links_from_the_map(self):
        js = (_SRC / "ion" / "web" / "static" / "js" / "app.js"
              ).read_text(encoding="utf-8")
        assert "/api/nav/permissions" in js
        assert "applyNavPermissionMap" in js

    def test_the_client_hides_empty_dropdown_groups(self):
        """A group whose every item is hidden should not stay as an empty
        menu -- which is what the old loop did for only three of them."""
        js = (_SRC / "ion" / "web" / "static" / "js" / "app.js"
              ).read_text(encoding="utf-8")
        assert "hideEmptyNavGroups" in js

    def test_the_sweep_runs_for_every_group_not_a_hardcoded_three(self):
        js = (_SRC / "ion" / "web" / "static" / "js" / "app.js"
              ).read_text(encoding="utf-8")
        block = js.split("function hideEmptyNavGroups")[1][:600]
        assert "querySelectorAll" in block
        assert "tw-drop" in block
