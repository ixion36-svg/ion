"""The architecture diagram, moved out of JavaScript and into a fragment.

architecture.html held ION's whole topology in three JavaScript arrays and an
icon map, and built each node's card with `innerHTML`. Every rule
frontend/ion-pages.css carries for `.arch-node`, `.node-card`, `.node-icon`,
`.node-name` and `.ring-label` was therefore unreachable from the stylesheet.

These tests are the pin for that move. The inventory cases exist because the
node list is the thing a hand-port drops a row from silently, and the link
cases exist because the JavaScript hid a bad edge behind
`if (!p1 || !p2) return` - an edge naming a node that no longer exists just
stopped being drawn.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from ion.web.templating import make_templates
from ion.web.ui import architecture as page
from ion.web.ui.architecture import FALLBACK_ICON, diagram_payload, icon_class

FRAGMENT = "_fragments/architecture_diagram.html"

PAGE_TEMPLATE = (
    Path(page.__file__).resolve().parents[1] / "templates" / "architecture.html"
)

#: Every node the pre-change JavaScript declared, read out of
#: INTERNAL_MODULES and EXTERNAL_SERVICES. Written out by hand on purpose: a
#: list derived from the new constants would pass even if the port lost a row.
EXPECTED_NODES = {
    "api": "API Router",
    "alerts": "Alerts Engine",
    "cases": "Case Manager",
    "observables": "Observables",
    "auth": "Auth Service",
    "database": "Storage",
    "ai_chat": "AI Analytics",
    "pcap": "PCAP Engine",
    "forensics": "Forensics",
    "logging": "Logging",
    "security": "Shield",
    "notifications": "Notify",
    "knowledge_base": "Knowledge",
    "templates": "Templates",
    "chat": "Team Chat",
    "skills": "Training",
    "elasticsearch": "Elasticsearch",
    "kibana": "Kibana",
    "ollama": "Ollama LLM",
    "gitlab": "GitLab",
    "opencti": "OpenCTI",
    "dfir_iris": "DFIR-IRIS",
}

#: Scenario id -> how many edges the pre-change WORKFLOW_PATHS declared.
EXPECTED_LINK_COUNTS = {
    "default": 11, "auth": 5, "detection": 4,
    "incident": 4, "ai": 4, "infra": 4,
}


def render(**ctx) -> str:
    return make_templates().env.get_template(FRAGMENT).render(**ctx)


def page_source() -> str:
    return PAGE_TEMPLATE.read_text(encoding="utf-8")


def page_script() -> str:
    """Only the page's `{% block scripts %}`, which is where the arrays lived.

    The whole file will not do: the sidebar's own prose names DFIR-IRIS,
    OpenCTI and Logging in scenario descriptions, which is static markup and
    not a second copy of the topology.
    """
    src = page_source()
    marker = "{% block scripts %}"
    assert marker in src, "the page has no scripts block to check"
    return src[src.index(marker):]


# ---------------------------------------------------------------------------
# Registration and permission
# ---------------------------------------------------------------------------


def test_the_module_exposes_a_mounted_router():
    """Discovery means nothing announces itself, so check it is really there.

    A fragment that is not mounted 404s, and a 404 on this page renders an
    empty diagram, which reads as "nothing is connected".
    """
    import ion.web.ui as ui

    assert "/ui/architecture/diagram" in {r.path for r in ui.router.routes}


def _route():
    import ion.web.ui as ui

    for r in ui.router.routes:
        if r.path == "/ui/architecture/diagram":
            return r
    raise AssertionError("the architecture fragment route is not mounted")


def _dependency_calls(route) -> list:
    out, stack = [], list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if dep.call is not None:
            out.append(dep.call)
        stack.extend(dep.dependencies)
    return out


def _required_permissions(route) -> list[str]:
    """The permission strings closed over by require_permission dependencies."""
    found = []
    for fn in _dependency_calls(route):
        if not getattr(fn, "__qualname__", "").startswith("require_permission."):
            continue
        cells = dict(zip(fn.__code__.co_freevars,
                         (c.cell_contents for c in (fn.__closure__ or ()))))
        name = cells.get("permission_name")
        if name:
            found.append(name)
    return found


def test_the_fragment_permission_is_the_pages_own_permission():
    """The fragment must not be a softer way in than the page it serves.

    This page has no JSON endpoint to mirror: its JavaScript fetched nothing,
    and /api/admin/architecture-health has no caller and returns health, not
    topology. So the authority compared against is server.py's own _PAGES
    row, read here rather than restated, so a change to the page's permission
    fails this test instead of quietly widening the fragment.
    """
    from ion.web.server import _PAGES

    page_perms = [p for _path, tpl, p in _PAGES if tpl == "architecture.html"]
    assert page_perms == ["security:read"], page_perms
    assert _required_permissions(_route()) == page_perms


def test_the_fragment_does_not_use_a_redirecting_page_dependency():
    for call in _dependency_calls(_route()):
        name = getattr(call, "__qualname__", "")
        assert "require_page_permission" not in name
        assert "require_page_auth" not in name


# ---------------------------------------------------------------------------
# The inventory that moved
# ---------------------------------------------------------------------------


def test_every_module_and_service_renders_a_node_card():
    html = render(payload=diagram_payload())
    for node_id, name in EXPECTED_NODES.items():
        assert f'data-id="{node_id}"' in html, node_id
        assert f">{name}</div>" in html, name
    assert html.count('class="arch-node"') == len(EXPECTED_NODES)


def test_every_node_sits_in_a_ring_the_page_can_position():
    """A node with no ring is never positioned, so it piles up at the origin."""
    html = render(payload=diagram_payload())
    nodes = re.findall(r'<div class="arch-node"([^>]*)>', html)
    assert len(nodes) == len(EXPECTED_NODES)
    for attrs in nodes:
        assert re.search(r'data-ring="\d+"', attrs), attrs


def test_icon_names_resolve_to_ion_classes_not_lucide_names():
    html = render(payload=diagram_payload())
    # `route` and `folder-open` are the two that are not a straight rename,
    # which is the whole reason the map existed.
    assert icon_class("route") == "icon-git-branch"
    assert icon_class("folder-open") == "icon-folder"
    assert 'class="icon-git-branch"' in html
    assert 'class="icon-folder"' in html
    assert 'class="route"' not in html


def test_an_unmapped_icon_name_falls_back_rather_than_rendering_blank():
    assert icon_class("no-such-lucide-icon") == FALLBACK_ICON
    assert icon_class("") == FALLBACK_ICON


def test_the_three_ring_labels_render_as_markup():
    html = render(payload=diagram_payload())
    for label in ("Core Cluster", "System Services", "External Integrations"):
        assert label in html, label
    assert html.count('class="ring-label"') == 3


def test_the_core_rings_zero_angle_offset_is_still_emitted():
    """The zero that matters on this page.

    The core ring's angle offset is 0. Written as a truthiness test the
    attribute would be dropped for exactly that ring, the page would read
    NaN out of it, and its four nodes would land at the container's origin
    stacked on top of each other. Zero is a measured offset, not a missing
    one, so the template uses `is not none`.
    """
    html = render(payload=diagram_payload())
    assert 'data-ring-angle-offset="0.0"' in html


def test_every_ring_emits_all_three_geometry_numbers():
    html = render(payload=diagram_payload())
    labels = re.findall(r'<div class="ring-label"(.*?)>', html, re.S)
    assert len(labels) == 3
    for attrs in labels:
        for attr in ("data-ring-min-radius", "data-ring-radius-factor",
                     "data-ring-angle-offset"):
            assert attr in attrs, (attr, attrs)


# ---------------------------------------------------------------------------
# The workflow links
# ---------------------------------------------------------------------------


def test_every_scenario_renders_its_edges_as_elements():
    html = render(payload=diagram_payload())
    for workflow, count in EXPECTED_LINK_COUNTS.items():
        found = html.count(f'data-workflow="{workflow}"')
        assert found == count, f"{workflow}: {found} edges, expected {count}"


def test_every_edge_names_a_node_that_exists_or_the_hub():
    """The check the JavaScript could not make.

    `drawConnections` did `if (!p1 || !p2) return`, so an edge naming a
    renamed or deleted module simply stopped being drawn and the diagram
    looked fine. Nothing said a connection had gone missing.
    """
    payload = diagram_payload()
    known = {payload["hub_id"]}
    for ring in payload["rings"]:
        known.update(n.id for n in ring.nodes)
    for workflow, links in payload["workflows"].items():
        for link in links:
            assert link.source in known, (workflow, link.source)
            assert link.target in known, (workflow, link.target)


# ---------------------------------------------------------------------------
# Escaping, which replaces the JavaScript's absence of any
# ---------------------------------------------------------------------------


def test_jinja_escapes_a_hostile_node_name():
    """The old renderNode interpolated `data.name` straight into an innerHTML
    string with no escaping at all."""
    hostile = page.Node(id="x", name="<script>alert(1)</script>", icon="icon-bug")
    ring = page.Ring(index=1, label="R", min_radius=1, radius_factor=0.1,
                     angle_offset=0.0, nodes=(hostile,))
    html = render(payload={"rings": (ring,), "workflows": {}, "hub_id": "hub"})
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# A failed build is not an empty system
# ---------------------------------------------------------------------------


def test_a_failed_build_says_so_and_prints_no_nodes():
    html = render(payload=None)
    assert "could not be read" in html
    assert "not an empty system" in html
    assert "arch-node" not in html
    assert "node-card" not in html
    assert "ring-label" not in html


def test_the_failed_branch_carries_its_own_retry_control():
    """The escape hatch has to be inside the swap.

    The page's status badge and header sit outside this fragment, so a failed
    first paint with no control in here leaves a blank diagram whose only
    remedy is reloading the page.
    """
    html = render(payload=None)
    assert 'hx-get="/ui/architecture/diagram"' in html
    assert 'hx-target="#arch-diagram-nodes"' in html
    assert "Retry" in html
    assert "data-arch-topology-failed" in html


def test_the_route_renders_the_failed_branch_when_the_build_raises(monkeypatch):
    from starlette.requests import Request

    def boom():
        raise RuntimeError("topology unavailable")

    monkeypatch.setattr(page, "diagram_payload", boom)
    request = Request({
        "type": "http", "method": "GET", "path": "/ui/architecture/diagram",
        "headers": [], "query_string": b"", "root_path": "",
    })
    body = page.architecture_diagram_fragment(request).body.decode("utf-8")
    assert "could not be read" in body
    assert "arch-node" not in body


# ---------------------------------------------------------------------------
# What is left in the page
# ---------------------------------------------------------------------------


def test_the_page_builds_no_markup_in_javascript():
    """The measurement the redesign's `server` column makes, asserted here so
    the page cannot regress without this file failing."""
    src = page_source()
    assert not re.search(r"innerHTML\s*\+?=", src)
    assert "insertAdjacentHTML" not in src
    assert not re.search(r"outerHTML\s*\+?=", src)


def test_the_page_holds_an_htmx_slot_rather_than_a_topology():
    src = page_source()
    assert 'id="arch-diagram-nodes"' in src
    assert 'hx-get="/ui/architecture/diagram"' in src
    assert 'hx-trigger="load"' in src
    # The constants and the two functions that built markup are gone, not
    # merely unused: a second copy of the topology is what drifts.
    for dead in ("INTERNAL_MODULES", "EXTERNAL_SERVICES", "WORKFLOW_PATHS",
                 "ICON_MAP", "renderNode", "updateLabels", "labels-container"):
        assert dead not in src, dead


@pytest.mark.parametrize("display_name", sorted(EXPECTED_NODES.values()))
def test_no_node_label_is_left_in_the_page(display_name):
    """One case per node, so a partial port names the row it left behind.

    These strings existed only inside the JavaScript arrays; nothing in the
    page's own script uses them. A copy left behind there is a second
    definition of a node's label, and the two drift.
    """
    assert display_name not in page_script()
