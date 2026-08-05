"""Route audit phase 7e — `/topology` merged into `/integrations`.

"Platform Topology" and "Integrations" rendered the SAME service set from the
SAME two endpoints (`/api/integrations/status`, `/api/integrations/healthcheck`)
— one as a hub-and-spoke diagram, one as a card list — while living in different
nav groups under different page permissions. Topology is now the second tab of
`/integrations` and the old route is a 302.

Two things this file is really guarding:

1. **The diagram must not initialise on DOMContentLoaded any more.** As a tab it
   starts `display:none`, and both `drawConnections()` and `createFlowSlide()`
   position nodes from `getBoundingClientRect()`, which reads 0x0 on a hidden
   element. Init is deferred to first tab-show. A future edit that "restores"
   the DOMContentLoaded bootstrap would silently collapse every connector line
   to the origin — visually broken, no error in the console.

2. **The merge must not have shadowed a symbol.** The two templates were
   concatenated into one global script scope; a duplicated top-level `const`
   would throw at parse time and take the whole page's JS down, including the
   Services tab that has nothing to do with topology.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ion.web.server import app

TEMPLATES = Path("src/ion/web/templates")


@pytest.fixture(scope="module")
def paths():
    return {r.path for r in app.routes}


@pytest.fixture(scope="module")
def integrations() -> str:
    return (TEMPLATES / "integrations.html").read_text(encoding="utf-8")


# ── route retirement ─────────────────────────────────────────────────────


def test_topology_route_still_served(paths):
    """Bookmarks and the sibling tab strip must not 404."""
    assert "/topology" in paths


def test_topology_template_is_gone():
    assert not (TEMPLATES / "topology.html").exists()


def test_topology_redirects_to_the_integrations_tab():
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        resp = client.get("/topology", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/integrations?tab=topology"


def test_redirect_is_not_auth_gated():
    """A redirect that 401s sends bookmark-followers to a login loop instead of
    the page they asked for. The destination does its own gating."""
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        resp = client.get("/topology", follow_redirects=False)
    assert resp.status_code == 302


# ── the merged page ──────────────────────────────────────────────────────


def test_both_tabs_present(integrations):
    assert 'data-tab="services"' in integrations
    assert 'data-tab="topology"' in integrations
    assert 'id="tab-services"' in integrations
    assert 'id="tab-topology"' in integrations


def test_services_tab_is_the_default(integrations):
    """Existing /integrations users must land where they always did."""
    assert 'id="tab-services" class="int-tab-panel active"' in integrations
    assert 'id="tab-topology" class="int-tab-panel"' in integrations


def test_deep_link_switches_to_topology(integrations):
    """The redirect appends ?tab=topology — the page has to honour it."""
    assert "URLSearchParams" in integrations
    assert "switchIntegrationsTab('topology')" in integrations


def test_topology_markup_came_across(integrations):
    for marker in ("topo-page-wrap", "topo-diagram", "topo-health-banner",
                   "flow-diagram", 'id="details-grid"'):
        assert marker in integrations, marker


def test_topology_css_came_across(integrations):
    """The diagram is unreadable without its own stylesheet — the styles moved
    with the markup rather than being left behind in a deleted file."""
    assert ".topo-node" in integrations
    assert ".topo-hub" in integrations


# ── the two real hazards ─────────────────────────────────────────────────


def _script_block(html: str) -> str:
    m = re.search(r"\{%\s*block scripts\s*%\}(.*)", html, re.S)
    assert m, "integrations.html has no scripts block"
    return m.group(1)


def test_topology_init_is_deferred_not_on_domcontentloaded(integrations):
    js = _script_block(integrations)
    assert "window.ionInitTopologyTab" in js
    # The geometry passes must be reachable only through the deferred entry
    # point, never from a DOMContentLoaded handler.
    for hidden_geometry_call in ("createServiceNodes();", "createFlowSlide();"):
        for m in re.finditer(re.escape(hidden_geometry_call), js):
            preceding = js[max(0, m.start() - 400):m.start()]
            assert "DOMContentLoaded" not in preceding.split("function ")[-1], (
                f"{hidden_geometry_call} runs from a DOMContentLoaded handler; "
                "the panel is display:none at that point and every node "
                "measures 0x0"
            )


def test_tab_switch_triggers_topology_init(integrations):
    js = _script_block(integrations)
    assert "ionInitTopologyTab" in js
    switcher = js[js.index("function switchIntegrationsTab"):]
    switcher = switcher[:switcher.index("\n}")]
    assert "topology" in switcher and "ionInitTopologyTab" in switcher


def test_reshow_redraws_connections(integrations):
    """Panel width can change while hidden, so a second show must re-measure."""
    js = _script_block(integrations)
    init = js[js.index("window.ionInitTopologyTab"):]
    init = init[:init.index("\n};")]
    assert "drawConnections()" in init


def test_no_duplicate_top_level_declarations(integrations):
    """Two page scripts concatenated into one global scope. A repeated
    top-level `const`/`let`/`function` is a parse-time SyntaxError that kills
    the Services tab too."""
    js = _script_block(integrations)
    names = re.findall(r"^(?:const|let|var|function|async function)\s+(\w+)", js, re.M)
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, f"duplicated top-level declaration(s) after the merge: {dupes}"


def test_click_actions_resolve_to_globals(integrations):
    """event-delegation.js looks actions up on `window`, so every
    data-click-action introduced by the merge needs a global of that name."""
    js = _script_block(integrations)
    actions = set(re.findall(r'data-click-action="(\w+)"', integrations))
    for action in {"switchIntegrationsTab", "refreshAll", "flowReset",
                   "flowRetreat", "flowAdvance", "flowAutoToggle"} & actions:
        assert re.search(rf"^(?:async )?function {action}\b", js, re.M) or \
               re.search(rf"window\.{action}\s*=", js), action


# ── nav coherence ────────────────────────────────────────────────────────


def test_sibling_strip_points_at_the_new_home():
    for tpl in ("network_map.html", "data_flow.html"):
        text = (TEMPLATES / tpl).read_text(encoding="utf-8")
        assert '"href": "/integrations?tab=topology"' in text, tpl
        assert '"href": "/topology"' not in text, tpl


def test_nav_no_longer_highlights_engineering_for_topology():
    """`/topology` never appears in the address bar now — it redirects — so a
    startswith('/topology') branch in the Engineering group would be dead code
    that also fights the Administration group for the active state."""
    base = (TEMPLATES / "base.html").read_text(encoding="utf-8")
    assert "p.startswith('/topology')" not in base
