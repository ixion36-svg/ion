"""The case attack-path graph's lanes, stats and legend.

AN UNREADABLE PAYLOAD READ AS "NO ATTACK PATH DERIVED YET"

    const nodes = data.nodes || [];
    ...
    if (nodes.length === 0) {
        container.innerHTML = '... No attack path derived yet</div>';

The HTTP failures were handled: a non-ok response said "Attack path
unavailable" and the catch said "Attack path failed to load". What was
not handled is a 200 whose body is the wrong shape, which became an empty
node list and then the sentence that says this case has no established
chain of activity.

The edge overlay stays in the page. `drawAttackPathEdges` reads
`getBoundingClientRect`, `scrollWidth` and `scrollLeft` to place each
curve, so it needs a laid-out DOM and there is nothing in it for a
stylesheet to reach. The fragment hands it the edges on the graph element
rather than making it fetch again, and its existing refusal to draw an
edge whose endpoint was not rendered is preserved: skip, never fabricate.
"""
from __future__ import annotations

import json
import re
from html import unescape
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.ui.cases import PERMISSION, router

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "src/ion/web/templates/cases.html"

URL = "/ui/cases/7/attack-path"


class _User:
    id = 1
    username = "cases-tester"

    def __init__(self, *permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _app(user):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: user
    application.dependency_overrides[get_db_session] = lambda: None
    return application


def _get(user):
    with TestClient(_app(user)) as client:
        return client.get(URL)


def _reader():
    return _User(PERMISSION)


def flat(html: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", html)).split())


@pytest.fixture
def path(monkeypatch):
    def set(payload=None, raises=None):
        def handler(case_id, current_user=None, session=None):
            if raises is not None:
                raise raises
            return payload

        monkeypatch.setattr("ion.web.ui.cases.read_attack_path", handler,
                            raising=False)

    return set


def _payload(**over):
    p = {
        "nodes": [{"id": "n1", "type": "host", "label": "WS-01",
                   "threat_level": "high"},
                  {"id": "n2", "type": "user", "label": "jdoe",
                   "threat_level": "low"}],
        "edges": [{"source": "n1", "target": "n2",
                   "type": "auth_presence"}],
        "phases": [{"tactic": "initial-access", "node_ids": ["n1"]},
                   {"tactic": "lateral-movement", "node_ids": ["n2"]}],
        "stats": {"nodes": 2, "alerts": 4, "edges": {"total": 1},
                  "tactics_reached": ["initial-access"],
                  "reaches_impact": False},
    }
    p.update(over)
    return p


# ---------------------------------------------------------------------------
# Gate
# ---------------------------------------------------------------------------


def test_the_panel_needs_the_pages_permission(path):
    path(payload=_payload())
    assert _get(_User()).status_code == 403
    assert _get(_reader()).status_code == 200


# ---------------------------------------------------------------------------
# The false "no attack path"
# ---------------------------------------------------------------------------


def test_an_unreadable_payload_is_not_no_attack_path(path):
    """The defect this panel exists to fix."""
    path(payload={"nodes": "two"})
    body = flat(_get(_reader()).text)
    assert "No attack path derived yet" not in body
    assert "not in a shape" in body


def test_a_body_that_is_not_a_mapping_is_not_no_attack_path(path):
    path(payload="broken")
    body = flat(_get(_reader()).text)
    assert "No attack path derived yet" not in body
    assert "could not" in body.lower() or "not in a shape" in body


def test_a_genuinely_empty_graph_still_says_so(path):
    path(payload=_payload(nodes=[], edges=[], phases=[]))
    assert "No attack path derived yet" in flat(_get(_reader()).text)


def test_a_failed_read_says_so(path):
    path(raises=RuntimeError("the deriver went away"))
    body = flat(_get(_reader()).text)
    assert "No attack path derived yet" not in body
    assert "could not" in body.lower()


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_the_stats_strip_reports_its_figures(path):
    path(payload=_payload())
    body = flat(_get(_reader()).text)
    assert "2 nodes" in body
    assert "1 edges" in body
    assert "4 alerts" in body


def test_a_missing_node_or_edge_count_falls_back_to_the_list_length(path):
    """The page did this and it is right: the list is the better answer."""
    path(payload=_payload(stats={}))
    body = flat(_get(_reader()).text)
    assert "2 nodes" in body
    assert "1 edges" in body


def test_a_missing_alert_count_is_not_reported_as_zero(path):
    """`stats.alerts != null ? stats.alerts : 0` said no alerts fed this
    path when the count was simply not recorded."""
    path(payload=_payload(stats={"nodes": 2}))
    html = _get(_reader()).text
    assert "0 alerts" not in flat(html)
    assert "an-absent" in html


def test_the_tactics_reached_are_listed_in_order(path):
    path(payload=_payload(stats={
        "tactics_reached": ["initial-access", "lateral-movement"]}))
    body = flat(_get(_reader()).text)
    assert "Initial Access" in body
    assert "Lateral Movement" in body
    assert body.index("Initial Access") < body.index("Lateral Movement")


def test_unreadable_tactics_do_not_read_as_none_reached(path):
    path(payload=_payload(stats={"tactics_reached": "initial-access"}))
    assert "an-absent" in _get(_reader()).text


def test_the_impact_badge_appears_only_when_the_path_reaches_impact(path):
    path(payload=_payload(stats={"reaches_impact": True}))
    assert "reaches impact" in flat(_get(_reader()).text)
    path(payload=_payload(stats={"reaches_impact": False}))
    assert "reaches impact" not in flat(_get(_reader()).text)


# ---------------------------------------------------------------------------
# Lanes
# ---------------------------------------------------------------------------


def test_a_node_lands_in_its_earliest_phase(path):
    """The page's rule: the earliest phase whose node_ids contains it."""
    path(payload=_payload(phases=[
        {"tactic": "initial-access", "node_ids": ["n1", "n2"]},
        {"tactic": "lateral-movement", "node_ids": ["n2"]}]))
    html = _get(_reader()).text
    first = html.index("initial-access") if "initial-access" in html \
        else html.index("Initial Access")
    second = html.index("Lateral Movement")
    assert first < html.index("jdoe") < second


def test_a_node_in_no_phase_falls_into_an_unattributed_lane(path):
    path(payload=_payload(phases=[
        {"tactic": "initial-access", "node_ids": ["n1"]}]))
    body = flat(_get(_reader()).text)
    assert "Unattributed" in body
    assert "jdoe" in body


def test_an_empty_lane_is_still_drawn(path):
    path(payload=_payload(phases=[
        {"tactic": "initial-access", "node_ids": ["n1"]},
        {"tactic": "exfiltration", "node_ids": []},
        {"tactic": "lateral-movement", "node_ids": ["n2"]}]))
    html = _get(_reader()).text
    assert "Exfiltration" in flat(html)
    assert "apg-lane-empty" in html


def test_a_node_with_no_label_falls_back_to_its_value_then_its_id(path):
    path(payload=_payload(nodes=[
        {"id": "n1", "value": "10.0.0.1"},
        {"id": "n2"}]))
    body = flat(_get(_reader()).text)
    assert "10.0.0.1" in body
    assert "n2" in body


def test_a_threat_level_outside_the_known_set_takes_no_class(path):
    path(payload=_payload(nodes=[
        {"id": "n1", "type": "host", "label": "H",
         "threat_level": "catastrophic"}]))
    html = _get(_reader()).text
    # The level was never visible text on the card: it lives in the
    # title, beside the type and the value, and in the class.
    assert "threat: catastrophic" in html
    assert "tl-catastrophic" not in html


def test_a_node_type_outside_the_glyph_table_gets_the_fallback(path):
    path(payload=_payload(nodes=[
        {"id": "n1", "type": "mailbox", "label": "M"}]))
    html = _get(_reader()).text
    assert ">?<" in html.replace(" ", "").replace("\n", "")


def test_a_node_label_is_escaped(path):
    path(payload=_payload(nodes=[
        {"id": "n1", "label": "<img src=x onerror=alert(1)>"}]))
    html = _get(_reader()).text
    assert "<img src=x" not in html


def test_nodes_that_are_not_a_list_are_reported(path):
    path(payload=_payload(nodes=[{"id": "n1"}], phases="early"))
    body = flat(_get(_reader()).text)
    assert "not in a shape" in body


# ---------------------------------------------------------------------------
# The legend and the edges handed to the overlay
# ---------------------------------------------------------------------------


def test_the_legend_lists_every_edge_type(path):
    path(payload=_payload())
    body = flat(_get(_reader()).text)
    for label in ("Process lineage", "Network flow", "Auth / presence",
                  "Shared observable"):
        assert label in body, label


def test_the_edges_reach_the_overlay_without_a_second_fetch(path):
    path(payload=_payload())
    html = _get(_reader()).text
    match = re.search(r"data-apg-edges='([^']*)'", html)
    assert match, html[:400]
    edges = json.loads(unescape(match.group(1)))
    # The label is resolved here too, because the overlay's own
    # _APG_EDGE_LABELS table moved into the fragment with the legend.
    assert edges == [{"source": "n1", "target": "n2",
                      "type": "auth_presence",
                      "label": "Auth / presence"}], edges


def test_an_unreadable_edge_list_hands_over_nothing_rather_than_guessing(
        path):
    path(payload=_payload(edges="one"))
    html = _get(_reader()).text
    match = re.search(r"data-apg-edges='([^']*)'", html)
    assert match
    assert json.loads(unescape(match.group(1))) == []
    assert "an-absent" in html


def test_an_edge_missing_an_endpoint_is_not_handed_over(path):
    """The overlay already refuses to draw one, with the right reason:
    skip, never fabricate. There is no sense sending it."""
    path(payload=_payload(edges=[
        {"source": "n1", "type": "network_flow"},
        {"source": "n1", "target": "n2", "type": "network_flow"}]))
    html = _get(_reader()).text
    edges = json.loads(unescape(
        re.search(r"data-apg-edges='([^']*)'", html).group(1)))
    assert len(edges) == 1, edges


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------


def _scripts() -> str:
    body = re.sub(r"\{#.*?#\}", "", PAGE.read_text(encoding="utf-8"),
                  flags=re.S)
    scripts = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", body,
                                   re.S))
    return re.sub(r"//[^\n]*", "", scripts)


def test_the_page_no_longer_builds_the_lanes():
    body = _scripts()
    assert "apg-lane-head" not in body
    assert "apg-stat" not in body
    assert "apg-legend-swatch" not in body
    assert "_APG_TYPE_GLYPH" not in body


def test_the_page_keeps_the_edge_overlay():
    """It places each curve from getBoundingClientRect and the graph's
    scroll offsets, so it needs a laid-out DOM and there is no markup in
    it for a stylesheet to reach."""
    body = _scripts()
    assert "function drawAttackPathEdges" in body
    assert "getBoundingClientRect" in body
    assert "ResizeObserver" in body


def test_the_overlay_still_refuses_to_draw_a_missing_endpoint():
    """The guard, not the comment that explains it.

    This first asserted the phrase "never fabricate" survived, against
    text with comments already stripped, so it could only ever have
    passed by accident. The behaviour is the early return when either
    endpoint is absent from the card map.
    """
    import re as _re

    body = _scripts()
    draw = _re.search(r"function drawAttackPathEdges\(.*?\n\}", body,
                      _re.S)
    assert draw, "drawAttackPathEdges"
    assert _re.search(r"if \(!s \|\| !t\)\s*return", draw.group(0)), (
        "the overlay must skip an edge whose endpoint was not rendered")
