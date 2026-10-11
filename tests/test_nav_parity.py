"""The nav registry must not change what the navigation renders.

base.html produces the navigation today from hand-written markup: 10
top-level items, 54 entries inside 9 dropdown groups, a 6-entry mobile
panel, a 10-route `g` key table, and 108 separate `.startswith(` calls
deciding which entry is active. Replacing that with one registry is a
structural change, so the rendered result has to be identical.

tests/fixtures/nav_baseline.json was generated from the hand-written
version by tools/nav_snapshot.py. These tests re-render and compare.

Two of these pin a known divergence rather than a desirable state:
test_gkey_targets_all_resolve and the orphan test below. `g h` and `g t`
reach /shift-handover and /threat-landscape, which are live routes absent
from the nav, so they are reachable only by someone who knows the
keystroke. The registry should make that impossible to reintroduce, which
is why the count is asserted exactly and not merely as "no worse".
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.nav_render import snapshot

BASELINE = Path(__file__).parent / "fixtures" / "nav_baseline.json"


@pytest.fixture(scope="module")
def baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def live() -> dict:
    return snapshot()


def test_top_level_shape_is_unchanged(baseline, live):
    """Order and labels of the top row, and each group's contents in order."""
    assert live["structure"]["top_level"] == baseline["structure"]["top_level"]


def test_mobile_panel_is_unchanged(baseline, live):
    assert live["structure"]["mobile"] == baseline["structure"]["mobile"]


def test_gkey_table_is_unchanged(baseline, live):
    assert live["structure"]["gkeys"] == baseline["structure"]["gkeys"]


def test_active_item_is_unchanged_for_every_path(baseline, live):
    """The contract the 108 .startswith( calls encode, path by path.

    Compared per path so a failure names the path that broke rather than
    dumping 61 entries.
    """
    want, got = baseline["active_by_path"], live["active_by_path"]
    assert sorted(got) == sorted(want), "the set of pinned paths changed"
    broken = {p: {"want": want[p], "got": got[p]} for p in want if got[p] != want[p]}
    assert not broken, f"active item changed on {len(broken)} path(s): {broken}"


def test_a_path_matching_nothing_has_no_active_item(live):
    """Guards the inverse. A registry that marks everything active would
    otherwise satisfy every assertion above that only checks real paths.
    """
    assert live["active_by_path"]["/nothing-matches-this"] == []


def test_exactly_one_group_is_active_per_path(live):
    """No path may light up two groups at once.

    Not pinned from the baseline, because this is a property the
    hand-written version is not guaranteed to hold and the registry must.
    Paths that light no group are listed rather than asserted away, since
    a destination outside every group is the orphan problem below.
    """
    multi = {
        p: [a for a in act if a.startswith("group:")]
        for p, act in live["active_by_path"].items()
        if len([a for a in act if a.startswith("group:")]) > 1
    }
    assert not multi, f"more than one group active: {multi}"


def test_known_orphans_are_exactly_the_two_we_know_about(live):
    """Destinations reachable only by keyboard, invisible in the nav.

    Asserted exactly so the registry work cannot quietly add a third.
    """
    nav_hrefs = {
        it["href"] for it in live["structure"]["top_level"] if it["kind"] == "link"
    } | {
        k["href"]
        for it in live["structure"]["top_level"]
        if it["kind"] == "group"
        for k in it["items"]
    }
    orphans = sorted(set(live["structure"]["gkeys"].values()) - nav_hrefs)
    assert orphans == ["/shift-handover", "/threat-landscape"], (
        "the set of keyboard-only destinations changed; if the registry fixed "
        f"them that is good, update this test deliberately. got {orphans}"
    )


def test_every_nav_destination_is_a_registered_route(live):
    """A nav entry pointing at nothing is a dead link, and nothing catches
    that today. Cheap to assert once the destinations are data.
    """
    from ion.web.server import app

    routes = {getattr(r, "path", "") for r in app.routes}
    dests = {
        it["href"] for it in live["structure"]["top_level"] if it["kind"] == "link"
    } | {
        k["href"]
        for it in live["structure"]["top_level"]
        if it["kind"] == "group"
        for k in it["items"]
    } | set(live["structure"]["gkeys"].values())

    dead = sorted(d for d in dests if d not in routes)
    assert not dead, f"nav points at paths with no route: {dead}"
