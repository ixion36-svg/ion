"""The knowledge graph's markup, moved out of JavaScript and into a fragment.

knowledge_graph.html built six pieces of markup from strings: two canvas
overlays, the `#kg-meta` counts and legend, the "no data to graph" overlay, the
selected node's detail card and the detail panel's placeholder. The CSS block
for this page says so twice in its own comments, which is the shape of the
problem the `server` column measures: the rules exist, the markup they style
was assembled in the browser, and a stylesheet sweep reported success.

What these tests pin is the part a hand-port gets wrong quietly. The counts are
measurements, so 0 and "not measured" have to render differently. The legend's
colours used to exist twice, once in the service and once in the page, so they
are asserted against the service. A failed read and an empty graph send an
analyst to do opposite things, so they are asserted to be different fragments.
Every one of these was mutated back to the defective behaviour and the test
below it was confirmed to go red.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.models.alert_triage import AlertCase, AlertCaseStatus
from ion.services import knowledge_graph_service
from ion.web.templating import make_templates
from ion.web.ui import knowledge_graph as page
from ion.web.ui.knowledge_graph import (
    FALLBACK_COLOR,
    GraphMarkup,
    LegendEntry,
    NodeDetail,
    graph_markup,
    legend_entries,
    node_details,
    router,
)

FRAGMENT = "_fragments/knowledge_graph.html"
ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "src/ion/web/templates"
PAGE = TEMPLATES / "knowledge_graph.html"
FRAGMENT_FILE = TEMPLATES / "_fragments/knowledge_graph.html"


def render(**ctx: Any) -> str:
    return make_templates().env.get_template(FRAGMENT).render(**ctx)


def page_source() -> str:
    return PAGE.read_text(encoding="utf-8")


def page_script() -> str:
    """Only the page's `{% block scripts %}`.

    The markup half of the file legitimately contains `kg-` ids and control
    attributes, so a check for a leftover JavaScript construct has to look at
    the script block alone or it matches the markup it is meant to replace.
    """
    source = page_source()
    start = source.index("{% block scripts %}")
    return source[start:]


def markup(**fields: Any) -> GraphMarkup:
    """A payload with every field named, so a test states what it varies."""
    base: dict[str, Any] = {
        "total_nodes": 0,
        "total_edges": 0,
        "has_nodes": False,
        "legend": (),
        "details": (),
    }
    base.update(fields)
    return GraphMarkup(**base)


def detail(**fields: Any) -> NodeDetail:
    base: dict[str, Any] = {
        "id": "case:1",
        "label": "CASE-1",
        "url": None,
        "meta": (("Type", "case"),),
    }
    base.update(fields)
    return NodeDetail(**base)


# ---------------------------------------------------------------------------
# The writes are gone, and so is what they needed
# ---------------------------------------------------------------------------


#: What tools/ui_redesign_status.py counts, copied so this test and the
#: column agree on what a write is. `hx-swap="innerHTML"` is htmx naming a
#: swap style, not a write, and a plain substring check fails on it.
WRITE_PATTERNS = (
    r"innerHTML\s*\+?=",
    r"insertAdjacentHTML",
    r"outerHTML\s*\+?=",
)


@pytest.mark.parametrize("pattern", WRITE_PATTERNS)
def test_the_page_assembles_no_markup(pattern: str) -> None:
    """The `server` column itself. A page that still writes markup from a
    string has places a restyle cannot reach, and nothing says which."""
    assert re.search(pattern, page_source()) is None


def test_the_hand_rolled_escaper_is_gone() -> None:
    """kgEsc existed only to make string concatenation safe. Jinja
    autoescapes, so keeping it would mean a second, weaker definition of
    escaping that the next person reaches for."""
    assert "kgEsc" not in page_source()


def test_the_legend_colours_are_not_duplicated_in_the_page() -> None:
    """The page carried its own hex map for the legend dots while the service
    carried one for the nodes. They agreed when this was written, which is
    exactly why a drift between them would have been invisible: the dot and
    the node it describes are never side by side."""
    script = page_script()
    # #58a6ff is deliberately absent from this list. It is also vis-network's
    # edge highlight colour, which is an option for the library rather than a
    # legend colour, so asserting on it would fail against correct code.
    for color in ("#d29922", "#3fb950", "#bc8cff", "#ffa657", "#79c0ff", "#f85149"):
        assert color not in script, f"legend colour {color} still in the page"


@pytest.mark.parametrize("path", [PAGE, FRAGMENT_FILE], ids=["page", "fragment"])
def test_no_hx_trigger_carries_an_event_filter(path: Path) -> None:
    """htmx compiles the `[...]` part of an hx-trigger by handing the
    expression to `Function()`. ION serves `script-src 'self' 'nonce-...'`
    with no 'unsafe-eval', so the compile throws an EvalError and the trigger
    never fires at all.

    This page shipped `hx-trigger="keyup[key=='Enter']"` and the Enter key did
    nothing. Nothing else on the page was affected, so it read as working, and
    neither the template nor the HTML the fragment returns shows it: only a
    browser console does. Hence a test rather than a comment. The tree-wide
    version of this guard belongs in test_ui_fragment_registry.py, which this
    conversion does not own, so the assertion here covers these two files.
    """
    triggers = re.findall(r'hx-trigger="([^"]*)"', path.read_text(encoding="utf-8"))
    for trigger in triggers:
        assert "[" not in trigger, (
            f"{path.name} has an hx-trigger event filter: {trigger!r}. htmx "
            "needs 'unsafe-eval' to compile it and ION does not serve it."
        )


def test_the_filters_are_a_real_form_so_enter_needs_no_key_handler() -> None:
    """The replacement for the filter above. A form submits on Enter natively,
    Refresh is its submit button so searching has one definition, and a
    browser with htmx off reloads the page rather than navigating to a bare
    fragment."""
    source = page_source()
    form = source[source.index("<form") : source.index("</form>")]
    for control in ('id="kg-seed"', 'id="kg-closed"', 'id="kg-limit"'):
        assert control in form, f"{control} is outside the form, so Enter skips it"
    assert 'type="submit"' in form
    assert 'action="/knowledge-graph"' in form
    # Any key listener at all, not the one spelling the old one used. The
    # replacement is the form submitting natively, so a handler reappearing
    # here means searching has two definitions again.
    assert re.search(r"addEventListener\(\s*['\"]key(down|up|press)['\"]",
                     page_script()) is None


def test_the_controls_stay_outside_the_swap_target() -> None:
    """A failed render must not remove the control that retries. The filters
    and Refresh are before the slot and send their values with hx-include."""
    source = page_source()
    slot = source.index('id="kg-panel"')
    for control in ('id="kg-seed"', 'id="kg-closed"', 'id="kg-limit"', ">Refresh<"):
        assert source.index(control) < slot, f"{control} is inside the swap target"
    assert 'hx-include="#kg-seed, #kg-closed, #kg-limit"' in source


# ---------------------------------------------------------------------------
# The counts are measurements
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "count,shown",
    [(None, "Unknown"), (0, "0"), (7, "7")],
)
def test_the_node_count_distinguishes_zero_from_unmeasured(count, shown) -> None:
    """Parametrised over all three states on purpose. A test that only pins
    None passes against `{% if x %}`, because None and 0 both take the else
    branch and only the 0 case tells them apart."""
    html = render(payload=markup(total_nodes=count))
    assert f"<strong>{shown}</strong> nodes" in html


@pytest.mark.parametrize(
    "count,shown",
    [(None, "Unknown"), (0, "0"), (12, "12")],
)
def test_the_edge_count_distinguishes_zero_from_unmeasured(count, shown) -> None:
    html = render(payload=markup(total_edges=count))
    assert f"<strong>{shown}</strong> edges" in html


@pytest.mark.parametrize("count,shown", [(None, "unknown"), (0, "0"), (4, "4")])
def test_a_legend_count_distinguishes_zero_from_unmeasured(count, shown) -> None:
    """A type whose last node just went away is a measured zero. Dropping its
    dot shrinks the legend silently, so the graph and the legend stop agreeing
    about which types exist."""
    entry = LegendEntry(type="case", count=count, color="#58a6ff")
    html = render(payload=markup(legend=(entry,)))
    assert f"case ({shown})" in html


# ---------------------------------------------------------------------------
# The legend
# ---------------------------------------------------------------------------


def test_a_type_with_no_nodes_gets_no_legend_entry() -> None:
    """What the JavaScript's `if (!counts[t]) continue` did for an absent key,
    kept. A dot for every type ION can model would describe a graph that is
    not on screen."""
    entries = legend_entries({"case": 3})
    assert [e.type for e in entries] == ["case"]


@pytest.mark.parametrize("count", [0, None, 3])
def test_a_type_the_stats_name_keeps_its_entry_whatever_its_count(count) -> None:
    """The same guard as the template's, one layer down, and it needed its own
    test: the template-level case builds a LegendEntry by hand, so a
    truthiness test here went unnoticed through a full mutation run. It drops
    a type whose count is a measured 0 and a type whose count went missing,
    which is two silent omissions from one defect, so the parameters cover a
    plain integer as well as the two blanks."""
    assert [(e.type, e.count) for e in legend_entries({"case": count})] == [
        ("case", count)
    ]


def test_a_legend_entry_takes_its_colour_from_the_service() -> None:
    """One definition of a type's colour, so the dot cannot drift from the
    node. Asserted against the service rather than a literal here, which would
    be a third copy of the same hex."""
    entries = {e.type: e.color for e in legend_entries({"case": 1, "observable": 1})}
    assert entries["case"] == knowledge_graph_service.NODE_COLORS["case"]["background"]
    assert (
        entries["observable"]
        == knowledge_graph_service.NODE_COLORS["observable"]["background"]
    )


def test_every_type_the_service_can_colour_has_a_place_in_the_order() -> None:
    """LEGEND_ORDER is an ordering, not an allowlist, and this is the test that
    keeps it from quietly becoming one.

    The claim the parked draft made here was that "actor" repaired a live
    defect: the page's hard-coded type list omitted it while the service had a
    colour for it. build_graph emits no actor node, so nothing was wrong on
    screen and a test arranging `{"actor": 2}` pins a payload production cannot
    produce. What is worth asserting is the invariant underneath: a type the
    service can draw either has a position here or is appended, and neither
    path can drop it.
    """
    for ntype in knowledge_graph_service.NODE_COLORS:
        shown = [e.type for e in legend_entries({ntype: 1})]
        assert shown == [ntype], f"{ntype} has a node colour and no legend entry"


def test_a_type_the_legend_does_not_name_is_still_shown() -> None:
    """A node type the service grows and nobody adds here would otherwise be
    in the graph with no dot explaining it. It gets the service's own fallback
    colour, so it reads as grey rather than as a missing dot."""
    entries = legend_entries({"case": 1, "spaceship": 5})
    assert [e.type for e in entries] == ["case", "spaceship"]
    assert entries[1].color == FALLBACK_COLOR


def test_the_legend_keeps_the_order_the_page_rendered_in() -> None:
    entries = legend_entries({"user": 1, "case": 1, "technique": 1, "alert": 1})
    assert [e.type for e in entries] == ["case", "alert", "user", "technique"]


def test_a_stats_block_with_no_type_counts_yields_no_legend() -> None:
    """Positive control for the guard above: a missing by_type must not raise
    into the route's except branch and report the read as failed."""
    assert legend_entries(None) == ()
    assert legend_entries({}) == ()


# ---------------------------------------------------------------------------
# Empty, failed, and the difference between them
# ---------------------------------------------------------------------------


def test_an_empty_graph_says_so_and_offers_no_canvas() -> None:
    html = render(payload=markup(has_nodes=False, total_nodes=0))
    assert 'data-kg-empty="true"' in html
    assert "No data to graph" in html
    assert 'id="kg-canvas"' not in html


def test_a_graph_with_nodes_gets_a_canvas_even_with_no_count() -> None:
    """The empty state is a claim about the node list, so it is read off the
    node list. Keyed on the count instead, a stats block that lost its total
    would tell an analyst the graph is empty while it has nodes to draw."""
    html = render(payload=markup(has_nodes=True, total_nodes=None))
    assert 'id="kg-canvas"' in html
    assert "No data to graph" not in html


def test_a_failed_read_is_not_an_empty_graph() -> None:
    """The two send an analyst to do opposite things: link some observables,
    or go and read the logs. One fragment for both would always send them to
    do the wrong one half the time."""
    html = render(payload=None)
    assert 'data-kg-read-failed="true"' in html
    assert "nothing about it was measured" in html
    assert "No data to graph" not in html
    assert 'data-kg-empty="true"' not in html


def test_the_failed_read_fragment_carries_a_way_back() -> None:
    """Chrome wraps both states. The swap that reports the failure replaced
    the panel, so without a control in here the panel is stranded."""
    html = render(payload=None)
    assert 'hx-get="/ui/knowledge-graph"' in html
    assert 'hx-target="#kg-panel"' in html
    assert ">Retry<" in html


def test_the_detail_panel_has_both_of_its_non_node_states() -> None:
    """The placeholder and the "not in the detail set" line are markup here
    rather than two more strings in the page."""
    html = render(payload=markup(has_nodes=True))
    assert 'id="kg-detail-hint"' in html
    assert "Select a node to see details" in html
    assert 'id="kg-detail-missing"' in html


# ---------------------------------------------------------------------------
# Node detail cards
# ---------------------------------------------------------------------------


def test_a_node_detail_card_is_rendered_hidden_and_keyed_by_id() -> None:
    html = render(payload=markup(has_nodes=True, details=(detail(id="host:web-01"),)))
    assert 'data-kg-node="host:web-01"' in html
    assert 'class="kg-detail-node hidden"' in html


def test_the_detail_meta_keeps_the_order_the_card_rendered_in() -> None:
    """The order is the thing a port of five `if` blocks reshuffles without
    anything looking wrong."""
    nodes = [
        {
            "id": "case:1",
            "label": "CASE-1",
            "type": "case",
            "severity": "high",
            "status": "open",
            "threat_level": "malicious",
            "obs_type": "ipv4",
        }
    ]
    meta = node_details(nodes)[0].meta
    assert meta == (
        ("Type", "case"),
        ("Severity", "high"),
        ("Status", "open"),
        ("Threat", "malicious"),
        ("", "ipv4"),
    )


def test_an_absent_detail_field_is_left_out_entirely() -> None:
    meta = node_details([{"id": "host:a", "label": "a", "type": "host"}])[0].meta
    assert meta == (("Type", "host"),)


def test_a_blank_detail_field_is_left_out_rather_than_rendered_empty() -> None:
    """"Severity: " with nothing after it reads as a broken template, and the
    pre-change `if (node.severity)` dropped it too."""
    meta = node_details(
        [{"id": "case:1", "label": "x", "type": "case", "severity": ""}]
    )[0].meta
    assert meta == (("Type", "case"),)
    html = render(payload=markup(has_nodes=True, details=node_details(
        [{"id": "case:1", "label": "x", "type": "case", "severity": ""}]
    )))
    assert "Severity:" not in html


def test_an_sqlenum_status_renders_its_value_not_its_repr() -> None:
    """The JSON endpoint gets the string for free because FastAPI serialises a
    str-mixin enum by value. A template renders "AlertCaseStatus.OPEN", and
    value equality still holds so a colour map keyed on the string keeps
    working and only the visible text is wrong."""
    nodes = [
        {
            "id": "case:1",
            "label": "CASE-1",
            "type": "case",
            "status": AlertCaseStatus.OPEN,
        }
    ]
    html = render(payload=markup(has_nodes=True, details=node_details(nodes)))
    assert f"Status: {AlertCaseStatus.OPEN.value}" in html
    assert "AlertCaseStatus." not in html


def test_a_label_is_escaped_rather_than_executed() -> None:
    """The assertion that replaces kgEsc. A case title is user-supplied and
    reaches the label through the service."""
    hostile = '<script>alert("x")</script>'
    html = render(payload=markup(has_nodes=True, details=(detail(label=hostile),)))
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_a_stored_url_with_a_script_scheme_does_not_become_a_link() -> None:
    """Jinja escapes characters, not schemes. The pre-change kgEsc had the
    same hole, so this is not a regression it fixes by accident: the filter
    has to be there on purpose."""
    html = render(
        payload=markup(has_nodes=True, details=(detail(url="javascript:alert(1)"),))
    )
    assert "javascript:" not in html
    assert "kg-detail-link" not in html


def test_a_site_relative_url_is_still_a_link() -> None:
    """Positive control. A filter that dropped everything would pass the test
    above and silently remove every working link on the page."""
    html = render(
        payload=markup(has_nodes=True, details=(detail(url="/cases?id=4"),))
    )
    assert 'href="/cases?id=4"' in html
    assert "kg-detail-link" in html


# ---------------------------------------------------------------------------
# The route, and its gate
# ---------------------------------------------------------------------------


def _permission(routes) -> set[str]:
    """Every permission name the given routes' dependencies close over."""
    found = set()
    for route in routes:
        stack = list(getattr(route.dependant, "dependencies", []))
        while stack:
            dep = stack.pop()
            fn = dep.call
            stack.extend(dep.dependencies)
            if not getattr(fn, "__qualname__", "").startswith("require_permission."):
                continue
            cells = dict(
                zip(
                    fn.__code__.co_freevars,
                    (c.cell_contents for c in (fn.__closure__ or ())),
                )
            )
            if "permission_name" in cells:
                found.add(cells["permission_name"])
    return found


def test_the_fragment_requires_exactly_the_json_endpoints_permission() -> None:
    """Read off both live routers rather than compared to a literal. A
    fragment softer than the API it mirrors is not visible in a diff, and a
    literal here would still pass after the API tightened."""
    from ion.web.knowledge_graph_api import router as api_router

    mine = _permission(router.routes)
    theirs = _permission(api_router.routes)
    assert theirs, "the JSON endpoint declares no permission, so this proves nothing"
    assert mine == theirs


def test_the_fragment_repeats_the_json_endpoints_case_limit_bounds() -> None:
    """Otherwise the fragment is a way to ask for a bigger read than the API
    allows, through the same service function."""
    from ion.web.knowledge_graph_api import graph_endpoint

    def bounds(fn):
        import inspect

        # The constraints live in `metadata` as annotated_types markers, not
        # as `.ge` / `.le` attributes on the Query. Reading the attributes
        # raises, which looks like the assertion failing on a real mismatch.
        field = inspect.signature(fn).parameters["case_limit"].default
        return (field.default, [repr(m) for m in field.metadata])

    mine = bounds(page.knowledge_graph_fragment)
    assert mine[1], "no bounds declared, so this proves nothing"
    assert mine == bounds(graph_endpoint)


@pytest.fixture
def app(session):
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    class _User:
        id = 1
        username = "tester"

        def has_permission(self, _name: str) -> bool:
            return True

    application = FastAPI()
    application.include_router(router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: _User()
    application.dependency_overrides[get_db_session] = lambda: session
    yield application
    application.dependency_overrides.clear()


def test_the_route_renders_a_real_case_through_the_shared_service(app, session) -> None:
    """Drives knowledge_graph_service.build_graph, which is the function
    /api/knowledge-graph calls. A stand-in here would let the fragment and the
    API disagree about what the filters mean."""
    session.add(
        AlertCase(
            case_number="CASE-0001",
            title="Suspicious logon",
            status=AlertCaseStatus.OPEN,
            severity="high",
            created_by_id=1,
        )
    )
    session.commit()

    with TestClient(app) as client:
        resp = client.get("/ui/knowledge-graph")

    assert resp.status_code == 200
    assert "CASE-0001" in resp.text
    assert "case (1)" in resp.text
    assert "<strong>1</strong> nodes" in resp.text
    assert "AlertCaseStatus." not in resp.text
    assert 'data-kg-read-failed="true"' not in resp.text


def test_the_route_reports_an_empty_graph_as_empty(app) -> None:
    with TestClient(app) as client:
        resp = client.get("/ui/knowledge-graph")
    assert resp.status_code == 200
    assert 'data-kg-empty="true"' in resp.text
    assert "<strong>0</strong> nodes" in resp.text
    assert 'data-kg-read-failed="true"' not in resp.text


def test_a_read_that_raises_returns_a_fragment_that_says_so(app, monkeypatch) -> None:
    """A 500 is swapped by nothing, so the panel would keep its loading
    spinner for ever and the page would look like it was still working."""

    def boom(*a, **kw):
        raise RuntimeError("database is on fire")

    monkeypatch.setattr(knowledge_graph_service, "build_graph", boom)
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/ui/knowledge-graph")

    assert resp.status_code == 200
    assert 'data-kg-read-failed="true"' in resp.text
    assert "database is on fire" not in resp.text
    assert 'data-kg-empty="true"' not in resp.text


def test_the_markup_payload_reuses_the_service(session, monkeypatch) -> None:
    """The arguments are forwarded unchanged. A fragment that re-derived the
    filters would answer a different question from the graph beside it."""
    seen = {}

    def spy(sess, **kwargs):
        seen.update(kwargs)
        return {"nodes": [], "edges": [], "stats": {}}

    monkeypatch.setattr(knowledge_graph_service, "build_graph", spy)
    graph_markup(session, case_limit=7, include_closed=True, seed_value="1.2.3.4")
    assert seen == {"case_limit": 7, "include_closed": True, "seed_value": "1.2.3.4"}


def test_a_stats_block_without_counts_reports_them_unmeasured(session, monkeypatch) -> None:
    """Where the `is not none` guards get a payload that exercises them."""

    def thin(sess, **kwargs):
        return {"nodes": [{"id": "case:1", "label": "x", "type": "case"}], "stats": {}}

    monkeypatch.setattr(knowledge_graph_service, "build_graph", thin)
    result = graph_markup(session)
    assert result.total_nodes is None
    assert result.total_edges is None
    assert result.has_nodes is True
    html = render(payload=result)
    assert "<strong>Unknown</strong> nodes" in html
    assert 'id="kg-canvas"' in html


def test_the_page_leaves_the_graph_itself_to_the_library() -> None:
    """The counterpart to the write checks. Nodes and edges are JavaScript
    objects a rendering library consumes, so they stay a fetch; rendering them
    through Jinja would put a library's input through a template."""
    script = page_script()
    assert "vis.DataSet" in script
    assert "/api/knowledge-graph" in script
    assert "kg-canvas" in script


def test_the_fragment_leaves_the_canvas_empty() -> None:
    """vis-network owns every child of its container. A node or an edge
    rendered in here would be wiped on the next draw and would be markup
    describing data, which is the change this conversion is not."""
    html = render(payload=markup(has_nodes=True, details=(detail(),)))
    canvas = re.search(r'<div id="kg-canvas"[^>]*>(.*?)</div>', html, re.S)
    assert canvas is not None
    assert canvas.group(1).strip() == ""


def test_the_page_writes_no_htmx_failure_handler_of_its_own() -> None:
    """static/js/htmx-errors.js is the one definition of what a failed
    fragment request means, including what an expired session does.

    The page does listen for htmx:afterSwap, which is not a failure handler:
    it is how the graph fetch learns a new canvas has arrived. The error
    events are the ones that must have a single owner.
    """
    source = page_source()
    assert "htmx:responseError" not in source
    assert "htmx:sendError" not in source
    assert "htmx:afterSwap" in source, "the graph fetch has no trigger left"


def test_an_sqlenum_threat_level_renders_its_value_not_its_repr() -> None:
    """The second live enum column on this page, and the one a test of status
    alone would not cover.

    Observable.threat_level is SQLEnum(ThreatLevel), so an observable node
    carries the member. `plain` is applied per field rather than per node, so
    one field being unwrapped says nothing about the next.
    """
    from ion.models.observable import ThreatLevel

    nodes = [
        {
            "id": "observable:1",
            "label": "1.2.3.4",
            "type": "observable",
            "threat_level": ThreatLevel.CRITICAL,
        }
    ]
    html = render(payload=markup(has_nodes=True, details=node_details(nodes)))
    assert f"Threat: {ThreatLevel.CRITICAL.value}" in html
    assert "ThreatLevel." not in html
