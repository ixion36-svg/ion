"""The landing page's four regions as server-rendered fragments.

dashboard_v2.html fetched four endpoints inside one `Promise.all`, each with
a `.catch(() => null)`, and wrote fourteen innerHTML sites. Each test below
names the defect it catches, and the arrangement is chosen so the defect is
reachable rather than merely described.

Nothing here asserts a substring over the page or the module *source*. A
page-level substring assertion passes on a comment, and these conversions
carry a lot of comments that quote what they removed: the module's docstring
alone contains the words "No active alerts", "all clear", "Loading alerts"
and "innerHTML". Every behavioural assertion is against rendered output, and
the two source guards strip comments first.

The tile assertions and the panel assertions go through separate extractors.
A figure appears in the out-of-band tile and in the panel beside it, so
`">0<" in html` is satisfied by whichever of the two the test did not mean,
and weakening the other one's gate leaves the test green.

The failure tests call the route with its read stubbed rather than rendering
the template with `failed=True`. The second shape proves the markup and never
that the route selects that state, which is exactly the half that was wrong
in the JavaScript: the markup for "Cases unavailable" was fine and the
selection was a lie.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.web.templating import make_templates
from ion.web.ui import dashboard_v2 as mod

ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "src/ion/web/templates"
PAGE = TEMPLATES / "dashboard_v2.html"
FRAGMENTS = sorted(TEMPLATES.glob("_fragments/dashboard_v2*.html"))

REGIONS = ("overview", "team-metrics", "my-cases", "handover")

#: Each region's swap target in the page shell. Anything a render of that
#: region could remove lives inside one of these.
TARGETS = ("alerts-panel", "dash-metrics", "cases-panel", "handover-panel")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def flat(text: str) -> str:
    """Whitespace collapsed, because the templates wrap their sentences.

    A prose assertion against a wrapped template looks for a phrase that
    arrives with a newline inside it and fails for a reason that has nothing
    to do with the page.
    """
    return re.sub(r"\s+", " ", text)


def text_of(html: str) -> str:
    """Rendered text with the tags removed and whitespace collapsed."""
    return flat(re.sub(r"<[^>]+>", " ", html)).strip()


def render(name: str, **ctx: Any) -> str:
    env = make_templates().env
    return env.get_template(f"_fragments/dashboard_v2_{name}.html").render(**ctx)


def _oob(html: str, slot: str) -> str:
    """One out-of-band element's own markup, by id.

    Matched to the end of the element rather than to the next `</div>`, so a
    tile containing nested divs is not truncated at the first close and a
    tile assertion cannot run off into the panel that follows it.
    """
    start = re.search(rf'<(\w+) id="{slot}" hx-swap-oob="true"', html)
    if start is None:
        start = re.search(rf'<(\w+) id="{slot}"[^>]*hx-swap-oob="true"', html)
    assert start is not None, f"no {slot} out-of-band element, so this proves nothing"
    tag = start.group(1)
    depth, pos = 0, start.start()
    for match in re.finditer(rf"<{tag}\b|</{tag}>", html[start.start():]):
        depth += 1 if match.group(0).startswith(f"<{tag}") else -1
        if depth == 0:
            pos = start.start() + match.end()
            break
    else:
        pytest.fail(f"{slot} is never closed")
    return html[start.start():pos]


def _element(html: str, element_id: str) -> str:
    """One element's markup by id, from its open tag to its matching close.

    Depth-tracked rather than matched to the next `</div>`, so an element
    holding nested divs is not truncated at the first close. `_oob` does the
    same for an out-of-band element; this one takes any id.
    """
    start = re.search(rf"<(\w+)[^>]*\sid=\"{element_id}\"", html)
    assert start is not None, f"no #{element_id}, so this proves nothing"
    tag = start.group(1)
    depth = 0
    for match in re.finditer(rf"<{tag}\b|</{tag}>", html[start.start():]):
        depth += 1 if match.group(0).startswith(f"<{tag}") else -1
        if depth == 0:
            return html[start.start():start.start() + match.end()]
    pytest.fail(f"#{element_id} is never closed")


def tile(html: str, slot: str) -> str:
    """One out-of-band tile's text, so a tile assertion cannot read a panel."""
    return text_of(_oob(html, slot))


def panel(html: str) -> str:
    """The region's main target only, with every out-of-band element removed.

    Kept separate from `tile` for the reason a mutation pass found on another
    conversion: a figure asserted over the whole fragment was being read off
    the summary tile all along, so weakening the panel's own gate changed
    nothing.
    """
    stripped = html
    for slot in re.findall(r'<\w+ id="([\w-]+)" hx-swap-oob="true"', html):
        stripped = stripped.replace(_oob(html, slot), "")
    for slot in re.findall(r'<\w+ id="([\w-]+)"[^>]*hx-swap-oob="true"', html):
        block = _oob(html, slot)
        stripped = stripped.replace(block, "")
    return stripped


def panel_text(html: str) -> str:
    return text_of(panel(html))


def strip_comments(text: str) -> str:
    """Jinja, HTML and single-line JavaScript comments removed.

    The whole point: this page's comments quote `innerHTML`, `escHtml` and
    `style.width` by name in order to explain their removal, so a
    whole-file substring assertion for any of them passes on the explanation.
    Three separate conversions were caught by this.
    """
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
    return text


# ---------------------------------------------------------------------------
# Payload fixtures
# ---------------------------------------------------------------------------


def alert(**over: Any) -> dict:
    base: dict[str, Any] = {
        "id": "abc-123",
        "severity": "critical",
        "title": "Credential dumping on DC01",
        "host": "dc01",
        "user": "svc_backup",
        "rule_name": "LSASS access",
        "mitre_tactic_name": "Credential Access",
        "mitre_technique_id": "T1003",
        "timestamp": "2026-10-12T09:00:00+00:00",
    }
    base.update(over)
    return base


def histogram(*counts: int) -> list[dict]:
    return [{"ts": f"2026-10-12T{h:02d}:00:00Z", "count": c}
            for h, c in enumerate(counts)]


def es_live(**over: Any) -> dict:
    base: dict[str, Any] = {
        "enabled": True,
        "connected": True,
        "alerts": [alert()],
        "total_alerts": 1,
        "critical_count": 1,
        "high_count": 0,
        "alerts_histogram": histogram(3, 5, 2, 0),
        "cluster_name": "ion-prod",
    }
    base.update(over)
    return base


ES_OFF_PAYLOAD = {
    "enabled": False, "connected": False, "alerts": [], "total_alerts": 0,
    "critical_count": 0, "high_count": 0, "alerts_histogram": [],
}

ES_UNREACHABLE_PAYLOAD = {
    "enabled": True, "connected": False, "alerts": [], "total_alerts": 0,
    "critical_count": 0, "high_count": 0,
    "error": "Elasticsearch connection failed",
}


class _Role:
    def __init__(self, name: str) -> None:
        self.name = name


class _User:
    """A caller, with the permissions it holds spelled out.

    `has_permission` is what `require_permission` calls, so a stub user is
    the whole permission split: no password is set for anybody and no session
    is created.
    """

    def __init__(
        self,
        permissions: tuple[str, ...] = ("alert:read", "case:read"),
        *,
        display_name: Optional[str] = "Alex Kaur",
        username: Optional[str] = "akaur",
        roles: tuple[str, ...] = ("soc_analyst", "detection_engineer"),
        focus: Optional[str] = "soc_analyst",
        user_id: int = 42,
    ) -> None:
        self._permissions = permissions
        self.id = user_id
        self.display_name = display_name
        self.username = username
        self.roles = [_Role(r) for r in roles]
        self._focus_role = _Role(focus) if focus else None

    def has_permission(self, name: str) -> bool:
        return name in self._permissions

    def has_any_permission(self, names: list[str]) -> bool:
        return any(n in self._permissions for n in names)


def cases_page(rows: list[dict], total: Optional[int] = None) -> dict:
    return {
        "cases": rows,
        "total": len(rows) if total is None else total,
        "limit": 100, "offset": 0, "returned": len(rows),
        "has_more": False, "sort": "updated_at", "order": "desc",
    }


def only_open(rows: list[dict], total: Optional[int] = None):
    """A `list_cases_page` stub that answers one status and not the other.

    The route asks once per non-closed status, so a stub returning the same
    rows for both doubles every figure and a count assertion then passes on
    arithmetic rather than on the route.
    """
    def fake(session, **kw):
        if kw.get("status") == "open":
            return cases_page(rows, total)
        return cases_page([], 0)
    return fake


def case(**over: Any) -> dict:
    base: dict[str, Any] = {
        "id": 9,
        "case_number": "CASE-0009",
        "title": "Beaconing from finance subnet",
        "status": "open",
        "severity": "high",
        "created_at": "2026-10-11T08:00:00+00:00",
        "updated_at": "2026-10-12T08:00:00+00:00",
        "closed_at": None,
        "assigned_to_id": 42,
        "assigned_to": "akaur",
        "alert_count": 3,
    }
    base.update(over)
    return base


def handover_report(**over: Any) -> dict:
    base: dict[str, Any] = {
        "cases": {"opened": 4, "closed": 2},
        "alerts": {"total_triaged": 17},
        "highlights": [
            {"level": "critical", "message": "2 critical case(s) opened during this shift"},
        ],
    }
    base.update(over)
    return base


@pytest.fixture
def client():
    """The four routes mounted where they really live, with auth stubbed."""
    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session

    application = FastAPI()
    application.include_router(mod.router, prefix="/ui")
    application.dependency_overrides[get_current_user] = lambda: _User()
    application.dependency_overrides[get_db_session] = lambda: object()
    with TestClient(application) as test_client:
        yield test_client
    application.dependency_overrides.clear()


def as_user(client: TestClient, user: _User) -> TestClient:
    from ion.auth.dependencies import get_current_user

    client.app.dependency_overrides[get_current_user] = lambda: user
    return client


# ---------------------------------------------------------------------------
# Permissions. Three across four reads, which is the point of this page
# ---------------------------------------------------------------------------


def _gates(route) -> set[str]:
    """Every permission a route's dependency factories closed over."""
    found: set[str] = set()
    stack = list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        call = dep.call
        if call is not None:
            base = (getattr(call, "__qualname__", "") or "").split(".")[0]
            if base in ("require_permission", "require_any_permission"):
                cells = dict(zip(
                    call.__code__.co_freevars,
                    (c.cell_contents for c in (call.__closure__ or ())),
                ))
                one = cells.get("permission_name")
                many = cells.get("permission_names")
                if isinstance(one, str):
                    found.add(one)
                if isinstance(many, (list, tuple, set)):
                    found.update(str(p) for p in many)
        stack.extend(dep.dependencies)
    return found


def _live_routes() -> dict[str, Any]:
    from ion.web.server import app

    return {
        (r.path, tuple(sorted(r.methods or ()))): r
        for r in app.routes
        if getattr(r, "dependant", None) is not None
    }


#: Each fragment and the JSON endpoint whose gate it must carry, exactly.
MIRRORS = {
    "/ui/dashboard-v2/overview": "/api/dashboard",
    "/ui/dashboard-v2/team-metrics": "/api/dashboard/team-metrics",
    "/ui/dashboard-v2/my-cases": "/api/cases",
    "/ui/dashboard-v2/handover": "/api/shift-handover/report",
}


@pytest.mark.parametrize("fragment,endpoint", sorted(MIRRORS.items()))
def test_each_fragment_gate_matches_the_endpoint_it_mirrors(fragment, endpoint):
    """Defect: a fragment softer, or stricter, than the API it mirrors.

    Read off the live routes rather than the decorators, so a gate
    contributed by a router mount counts and a factory-built dependency
    reports its real argument. This is the assertion that fails if somebody
    "tidies" the overview route by giving it alert:read, which would hide the
    alert feed from a viewer /api/dashboard serves today, and the one that
    fails if the cases fragment loses case:read and becomes a softer way into
    case data than GET /api/cases.
    """
    routes = _live_routes()
    fragment_route = routes[(fragment, ("GET",))]
    endpoint_route = routes[(endpoint, ("GET",))]
    assert _gates(fragment_route) == _gates(endpoint_route)


def test_the_three_permissions_really_are_three_different_ones():
    """Positive control. If every endpoint carried the same gate, the test
    above would be satisfied by one constant and the split would be
    unmotivated."""
    routes = _live_routes()
    gates = {ep: frozenset(_gates(routes[(ep, ("GET",))]))
             for ep in MIRRORS.values()}
    assert gates["/api/dashboard"] == frozenset()
    assert gates["/api/dashboard/team-metrics"] == frozenset({"alert:read"})
    assert gates["/api/shift-handover/report"] == frozenset({"alert:read"})
    assert gates["/api/cases"] == frozenset({"case:read"})


def test_the_bare_auth_overview_route_is_listed_as_a_deliberate_drop():
    """Defect: the one that broke three other conversions.

    /ui/dashboard-v2/overview carries no named permission, correctly, because
    GET /api/dashboard carries none either. The shared registry suite asserts
    set equality between the fragments that are on bare authentication and the
    fragments listed as being on bare authentication on purpose, so an
    unlisted bare route turns that suite red for every worker in the
    checkout, not just for this page. An automated driver read that red suite
    as three other conversions' own failure and rolled them back.

    Asserted from this file as well, the way test_ui_fragment_profile.py does
    for its two, so the entry cannot be dropped by someone tidying the list
    without a test naming this page failing.
    """
    from tests.unit.test_ui_fragment_registry import BARE_AUTH_FRAGMENTS

    assert "/ui/dashboard-v2/overview" in BARE_AUTH_FRAGMENTS
    for region in ("team-metrics", "my-cases", "handover"):
        assert f"/ui/dashboard-v2/{region}" not in BARE_AUTH_FRAGMENTS


def test_a_viewer_without_case_read_still_gets_the_alert_regions(client, monkeypatch):
    """Defect: one permission for the whole page.

    A single route would have to carry the loosest gate, making the open-case
    list a softer way into case data than GET /api/cases, or the strictest,
    hiding the alert feed from an account that can read alerts. This is the
    arrangement that proves neither happens.

    The 403 is asserted on the body as well as the code, because the thing
    this page must not do is answer a refusal with an empty case list that
    reads as a quiet queue. An empty 200 would satisfy a status-only check in
    the one direction that matters.
    """
    from ion.web import api

    monkeypatch.setattr(
        api, "team_metrics_payload",
        lambda session: {"mttr_hours": 3.0, "closure_rate_7d": 80.0,
                         "created_7d": 5},
    )
    as_user(client, _User(permissions=("alert:read",)))

    allowed = client.get("/ui/dashboard-v2/team-metrics")
    assert allowed.status_code == 200
    assert "30d rolling" in panel_text(allowed.text)

    refused = client.get("/ui/dashboard-v2/my-cases")
    assert refused.status_code == 403
    assert "No open cases assigned to you" not in refused.text


def test_a_viewer_with_case_read_but_not_alert_read_gets_the_cases_region(
    client, monkeypatch
):
    """The other half, so neither result is an accident of ordering."""
    from ion.services import case_query_service as cq

    monkeypatch.setattr(
        cq, "list_cases_page", only_open([case()])
    )
    as_user(client, _User(permissions=("case:read",)))

    assert client.get("/ui/dashboard-v2/my-cases").status_code == 200
    assert client.get("/ui/dashboard-v2/team-metrics").status_code == 403
    assert client.get("/ui/dashboard-v2/handover").status_code == 403


# ---------------------------------------------------------------------------
# A failed read is not empty data. Selected by the route, not by the template
# ---------------------------------------------------------------------------


def _boom(*args: Any, **kwargs: Any):
    raise RuntimeError("the store refused")


async def _boom_async(*args: Any, **kwargs: Any):
    raise RuntimeError("the store refused")


def test_a_failed_overview_read_does_not_say_the_queue_is_quiet(
    client, monkeypatch, caplog
):
    """Defect: `.catch(() => null)` on /api/dashboard.

    The old page did worse than show an empty state: the feed was only ever
    written inside `if (es)`, so a failed read left #alerts-feed reading
    "Loading alerts..." for ever, and the hero counts kept their em-dashes.
    Either way the analyst is told nothing is wrong.
    """
    from ion.web import api

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", _boom_async)
    with caplog.at_level("ERROR"):
        response = client.get("/ui/dashboard-v2/overview")

    assert response.status_code == 200
    body = panel_text(response.text)
    assert "could not be read" in body
    assert "No active alerts" not in body
    assert "Loading alerts" not in response.text
    assert "Dashboard overview could not be read" in caplog.text


def test_a_failed_overview_read_still_greets_the_viewer(client, monkeypatch):
    """The user comes from the dependency, not from the read.

    Defect: folding the identity into the Elasticsearch try, which would
    blank the viewer's own name because a different store was down. The
    JavaScript had the inverse of this, and worse: a /api/dashboard failure
    took out the open-cases panel too, because the username it filtered on
    came from that read.
    """
    from ion.web import api

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", _boom_async)
    response = client.get("/ui/dashboard-v2/overview")
    assert tile(response.text, "welcome-name") == "Alex"


def test_a_failed_overview_read_draws_no_sparkline(client, monkeypatch):
    """Defect: a flat line along the floor for an unmeasured window, which is
    where a genuinely quiet window would also sit."""
    from ion.web import api

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", _boom_async)
    response = client.get("/ui/dashboard-v2/overview")
    assert "<svg" not in _oob(response.text, "kpi-open-alerts")
    assert "read failed" in tile(response.text, "kpi-open-alerts")


def test_a_failed_metrics_read_does_not_print_a_zero_rate(
    client, monkeypatch, caplog
):
    """Defect: `if (metrics)` skipping silently.

    The page kept its own em-dash placeholders, which read as measured and
    absent, and the closure-rate bar stayed at `w-[0%]`, drawing a graphic
    zero for a measurement nobody took.
    """
    from ion.web import api

    monkeypatch.setattr(api, "team_metrics_payload", _boom)
    with caplog.at_level("ERROR"):
        response = client.get("/ui/dashboard-v2/team-metrics")

    assert response.status_code == 200
    assert "read failed, not measured" in panel_text(response.text)
    assert "data-ion-style" not in response.text
    assert "Dashboard team metrics could not be read" in caplog.text


def test_a_failed_cases_read_does_not_say_no_open_cases(
    client, monkeypatch, caplog
):
    """Defect: "Cases unavailable (permission required)." for every failure.

    It asserted a cause it did not know. A 500 from the database is not a
    permission problem, and the permission case is now a 403 the global
    handler words.
    """
    from ion.services import case_query_service as cq

    monkeypatch.setattr(cq, "list_cases_page", _boom)
    with caplog.at_level("ERROR"):
        response = client.get("/ui/dashboard-v2/my-cases")

    assert response.status_code == 200
    body = panel_text(response.text)
    assert "could not be read" in body
    assert "No open cases assigned to you" not in body
    assert "permission required" not in response.text
    assert "not counted" in tile(response.text, "kpi-my-cases")
    assert "Dashboard open cases could not be read" in caplog.text


def test_a_failed_handover_read_does_not_print_three_zeros(
    client, monkeypatch, caplog
):
    """Defect: `statsEl.replaceChildren()` plus "Handover unavailable."

    The three figures vanished with no explanation while the list below said
    something else, so the strip read as a shift with nothing in it.
    """
    from ion.services import shift_handover_service

    monkeypatch.setattr(shift_handover_service, "generate_shift_report", _boom)
    with caplog.at_level("ERROR"):
        response = client.get("/ui/dashboard-v2/handover")

    assert response.status_code == 200
    body = panel_text(response.text)
    assert "could not be read" in body
    assert "This is not a quiet shift" in body
    assert "opened" not in body
    assert "Dashboard shift handover could not be read" in caplog.text


def test_one_dead_region_leaves_the_other_three_rendered(client, monkeypatch):
    """Defect: the whole reason there are four routes rather than one.

    Four `try` blocks inside one route keep the regions independent of each
    other's exceptions but not of the one HTTP request. This arranges the
    failure the shared-request shape cannot survive -- the overview read
    raising -- and asserts the other three still carry their data, which is
    what separate routes buy.

    The old page had the inverse and worse: a /api/dashboard failure silently
    blanked the open-cases panel too, because the username it filtered on came
    from that read, so neither the success branch nor the `=== null` branch
    fired and the panel kept its "Loading cases..." placeholder.
    """
    from ion.services import case_query_service as cq
    from ion.services import shift_handover_service
    from ion.web import api

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", _boom_async)
    monkeypatch.setattr(
        api, "team_metrics_payload",
        lambda session: {"mttr_hours": 2.0, "closure_rate_7d": 75.0,
                         "created_7d": 8},
    )
    monkeypatch.setattr(cq, "list_cases_page", only_open([case()], total=7))
    monkeypatch.setattr(
        shift_handover_service, "generate_shift_report",
        lambda session, hours: handover_report(),
    )

    dead = client.get("/ui/dashboard-v2/overview")
    assert dead.status_code == 200
    assert "could not be read" in panel_text(dead.text)

    metrics = client.get("/ui/dashboard-v2/team-metrics")
    assert "read failed" not in panel_text(metrics.text)
    assert "2h 0m" in panel_text(metrics.text)

    cases = client.get("/ui/dashboard-v2/my-cases")
    assert "could not be read" not in panel_text(cases.text)
    assert "My open cases 7" in tile(cases.text, "kpi-my-cases")

    handover = client.get("/ui/dashboard-v2/handover")
    assert "could not be read" not in panel_text(handover.text)
    assert "4 opened" in panel_text(handover.text)


def test_a_failed_overview_read_keeps_the_roles_it_holds_in_its_hand(
    client, monkeypatch
):
    """Defect: saying "Roles not read" for something no store was asked for.

    The roles and the greeting come from the get_current_user dependency, so a
    failed Elasticsearch query cannot have lost them. Claiming otherwise is
    the same dishonesty as printing a zero for an unmeasured count, pointing
    the other way: it reports an absence that is not there.
    """
    from ion.web import api

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", _boom_async)
    status = tile(client.get("/ui/dashboard-v2/overview").text, "dash-status")

    assert "Soc Analyst" in status
    assert "Detection Engineer" in status
    assert "Roles not read" not in status
    # The Elasticsearch pill shares this out-of-band block and did fail, so it
    # has to still say so: the point is which of the two lost its data.
    assert "Status not read" in status


def test_an_account_holding_no_role_says_so_rather_than_inventing_one():
    """Defect: `roleLabel(undefined)` returning the word "User", which names a
    role ION does not define, rendered in the pill that shows the focus role."""
    viewer = mod._viewer(_User(roles=(), focus=None))
    assert viewer["has_roles"] is False
    assert viewer["roles"] == []


# ---------------------------------------------------------------------------
# Elasticsearch's three states, which `|| 0` collapsed into one
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload,expected",
    [
        (ES_OFF_PAYLOAD, mod.ES_OFF),
        (ES_UNREACHABLE_PAYLOAD, mod.ES_UNREACHABLE),
        (es_live(), mod.ES_LIVE),
    ],
)
def test_the_three_elasticsearch_states_are_told_apart(payload, expected):
    """Defect: `if (es)` and `es.connected`, which is two states for three.

    Parametrised over all three rather than over the absent one, because the
    off and unreachable payloads are byte-identical in every count: only the
    two flags differ, so a test that arranged one of them would pass under
    the collapse this guards.
    """
    assert mod._es_state(payload) == expected


def test_an_unreachable_elasticsearch_is_not_a_quiet_queue(client, monkeypatch):
    """Defect: `es.critical_count || 0` on a payload of zeros.

    This is the single most damaging thing the page did. Elasticsearch
    refusing the query arrives as `connected: false` with every count at
    zero, and the page rendered "0 critical", an open-alerts tile of 0 and
    "No active alerts." Those are the three things an analyst reads before
    deciding the shift is quiet.
    """
    from ion.web import api

    async def unreachable():
        return dict(ES_UNREACHABLE_PAYLOAD)

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", unreachable)
    response = client.get("/ui/dashboard-v2/overview")

    body = panel_text(response.text)
    assert "did not answer" in body
    assert "not a quiet queue" in body
    assert "No active alerts" not in body
    assert "0 critical" not in body
    assert "Elasticsearch unreachable" in tile(response.text, "kpi-open-alerts")
    assert "unknown, not zero" in tile(response.text, "welcome-message")


def test_elasticsearch_switched_off_is_not_an_empty_queue(client, monkeypatch):
    """Defect: the same `|| 0`, reached by the other route.

    Nothing was asked, so nothing can be reported. The old page said
    "Elasticsearch degraded" in the status pill, which is wrong in the other
    direction: a store nobody configured is not degraded.
    """
    from ion.web import api

    async def off():
        return dict(ES_OFF_PAYLOAD)

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", off)
    response = client.get("/ui/dashboard-v2/overview")

    body = panel_text(response.text)
    assert "not configured" in body
    assert "not an empty queue" in body
    assert "No active alerts" not in body
    assert "Elasticsearch not configured" in tile(response.text, "kpi-open-alerts")


def test_a_live_empty_queue_does_say_no_active_alerts(client, monkeypatch):
    """The finding the two tests above must not be allowed to swallow.

    Without this they are satisfied by a page that never says the queue is
    clear, which is its own lie: a genuinely clear queue is the measurement
    an analyst most wants. A real zero, not a missing key, is what makes
    truthiness and `is not none` disagree here.
    """
    from ion.web import api

    async def quiet():
        return es_live(
            alerts=[], total_alerts=0, critical_count=0, high_count=0,
            alerts_histogram=histogram(0, 0, 0, 0),
        )

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", quiet)
    response = client.get("/ui/dashboard-v2/overview")

    body = panel_text(response.text)
    assert "No active alerts." in body
    assert "0 critical" in body
    # The footer count has its own gate on the same number, and a mutation
    # pass found it surviving truthiness: a counted zero was being reported as
    # a total nobody counted, in the one line that says what the figure is of.
    assert "of 0 open in the last 24h" in body
    assert "was not counted" not in body
    assert "Open alerts · 24h 0 " in tile(response.text, "kpi-open-alerts")
    assert "Your queue is clear" in tile(response.text, "welcome-message")


# ---------------------------------------------------------------------------
# The capped total, which is the page's biggest wrong number
# ---------------------------------------------------------------------------


def test_the_24h_total_is_the_histogram_sum_not_the_row_count(client, monkeypatch):
    """Defect: `$('kpi-open-alerts').textContent = es.total_alerts`.

    `total_alerts` is `len(alerts)` behind `limit=10`, so the headline on
    ION's landing page could never exceed 10 however many alerts were open.
    The histogram in the same payload is a real aggregation over the same
    window, so the arrangement here is a 10-row page under a histogram
    summing to 137: the tile must say 137.
    """
    from ion.web import api

    async def capped():
        return es_live(
            alerts=[alert(id=f"a{i}") for i in range(10)],
            total_alerts=10,
            alerts_histogram=histogram(*([5] * 27 + [2])),
        )

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", capped)
    response = client.get("/ui/dashboard-v2/overview")

    assert "Open alerts · 24h 137" in tile(response.text, "kpi-open-alerts")
    assert "of 137 open in the last 24h" in panel_text(response.text)


def test_the_severity_counts_say_what_they_were_counted_over(client, monkeypatch):
    """Defect: "3 critical" presented as a 24-hour figure.

    The counts really are over the rows the read returned, so the line has to
    say so rather than letting the reader take them for the window's totals.
    """
    from ion.web import api

    async def capped():
        return es_live(
            alerts=[alert(id=f"a{i}") for i in range(10)],
            total_alerts=10, critical_count=3, high_count=4,
            alerts_histogram=histogram(*([5] * 27 + [2])),
        )

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", capped)
    body = panel_text(client.get("/ui/dashboard-v2/overview").text)
    assert "3 critical" in body
    assert "in the 10 most recent" in body


def test_a_histogram_the_read_did_not_carry_is_not_counted_as_zero(
    client, monkeypatch
):
    """Defect: `es.alerts_histogram || []` then summing it.

    An absent histogram summed to 0, which would now print a confident zero
    into the tile that just stopped reporting a capped row count.
    """
    from ion.web import api

    async def no_histogram():
        payload = es_live()
        payload.pop("alerts_histogram")
        return payload

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", no_histogram)
    response = client.get("/ui/dashboard-v2/overview")
    assert "no histogram in this read" in tile(response.text, "kpi-open-alerts")
    assert "24h 0" not in tile(response.text, "kpi-open-alerts")

    # The severity counts are a separate measurement from the histogram, so an
    # unusable histogram must not take them down with it. The sentence reports
    # what it has and claims no 24-hour total.
    sentence = tile(response.text, "welcome-message")
    assert "1 critical" in sentence
    assert "in the last 24h" not in sentence


def test_the_24h_gate_decides_the_sentence_rather_than_decorating_it(
    client, monkeypatch
):
    """The gate this branch structure exists for.

    A flat chain put `total_24h is not none` after a branch that had already
    taken every falsy value a number can have, so the gate could not fail and
    a mutation pass could not tell it from truthiness. The value's split is
    nested under one gate now, and these are the three outcomes that gate
    selects between: a counted zero, a counted total, and no total at all.
    """
    from ion.web import api

    async def payload(**over):
        return es_live(**over)

    monkeypatch.setattr(
        api, "dashboard_elasticsearch_payload",
        lambda: payload(alerts=[], total_alerts=0, critical_count=0,
                        high_count=0, alerts_histogram=histogram(0, 0)),
    )
    assert "Your queue is clear" in tile(
        client.get("/ui/dashboard-v2/overview").text, "welcome-message")

    monkeypatch.setattr(
        api, "dashboard_elasticsearch_payload",
        lambda: payload(critical_count=0, high_count=0,
                        alerts_histogram=histogram(2, 3)),
    )
    counted = tile(client.get("/ui/dashboard-v2/overview").text, "welcome-message")
    assert "5 open alerts in the last 24h" in counted
    assert "was not counted" not in counted

    monkeypatch.setattr(
        api, "dashboard_elasticsearch_payload",
        lambda: payload(critical_count=0, high_count=0, alerts_histogram=[]),
    )
    uncounted = tile(client.get("/ui/dashboard-v2/overview").text,
                     "welcome-message")
    assert "was not counted" in uncounted


def test_no_sentence_prints_the_word_none_where_a_figure_goes(
    client, monkeypatch
):
    """Defect: a clause about the sample printed without gating on the sample.

    The counts are set all-or-none so that one missing figure cannot put the
    word "None" into the middle of a sentence. The histogram is a separate
    measurement, though, so a read can carry a usable total and no counts at
    all, and that combination reaches a branch gated on the total rather than
    on the counts. An independent review found it by reading the branches; it
    is arranged here so it cannot come back.
    """
    from ion.web import api

    async def total_but_no_counts():
        payload = es_live(alerts_histogram=histogram(2, 3))
        del payload["critical_count"]
        return payload

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload",
                        total_but_no_counts)
    response = client.get("/ui/dashboard-v2/overview")

    sentence = tile(response.text, "welcome-message")
    assert "5 open alerts in the last 24h" in sentence
    assert "None" not in sentence
    assert "most recent" not in sentence
    # And nowhere else on the fragment either.
    assert "None" not in text_of(response.text)


# ---------------------------------------------------------------------------
# The sparkline, computed where the count is
# ---------------------------------------------------------------------------


def test_the_sparkline_spans_the_viewbox_and_closes_its_fill():
    """Defect: a path that does not reach the edges, or a fill that is not a
    closed shape, which renders as a stroke over a transparent wedge."""
    spark = mod._spark_path(histogram(0, 4, 2))
    assert spark is not None
    xs = [float(p.split(",")[0][1:]) for p in spark["line"].split(" ")]
    assert xs[0] == pytest.approx(mod.SPARK_PAD)
    assert xs[-1] == pytest.approx(mod.SPARK_W - mod.SPARK_PAD)
    assert xs == sorted(xs)
    assert spark["line"].startswith("M")
    assert spark["fill"].endswith("Z")
    assert spark["fill"].startswith(spark["line"])


def test_the_sparkline_puts_a_higher_count_nearer_the_top():
    """Defect: an un-inverted y, which draws the shape upside down and makes
    a busy hour look like a quiet one."""
    spark = mod._spark_path(histogram(0, 9))
    ys = [float(p.split(",")[1]) for p in spark["line"].split(" ")]
    assert ys[1] < ys[0]


@pytest.mark.parametrize("buckets", [[], histogram(4), None, "not a list"])
def test_nothing_is_drawn_without_at_least_two_points(buckets):
    """Defect: a one-point histogram drawn as a flat line, which is the same
    shape an unmeasured window would get."""
    assert mod._spark_path(buckets) is None


def test_a_bucket_without_a_count_draws_nothing_rather_than_a_dip():
    """Defect: `b.count || 0`.

    `get_alerts_histogram` zero-fills with extended_bounds and returns an
    empty list on any failure, so a bucket with no count is a shape nobody
    produces. Substituting zero for it draws a dip no measurement supports.
    A string is arranged as well as a missing key, because a non-numeric
    value is the case `|| 0` also swallowed.
    """
    assert mod._spark_path([{"ts": "x"}, {"ts": "y", "count": 3}]) is None
    assert mod._spark_path(
        [{"ts": "x", "count": "3"}, {"ts": "y", "count": 3}]
    ) is None
    assert mod._spark_path(
        [{"ts": "x", "count": True}, {"ts": "y", "count": 3}]
    ) is None


# ---------------------------------------------------------------------------
# Team metrics. None means something specific and is not a failure
# ---------------------------------------------------------------------------


def test_no_closures_in_thirty_days_is_said_rather_than_dashed(
    client, monkeypatch
):
    """Defect: the same em-dash for "nothing closed" and "we could not look".

    `mttr_hours` is None when no case closed in the window, which is a
    finding about a quiet month. The JavaScript's `if (h == null) return '—'`
    printed the same character the page shows for a failed read.
    """
    from ion.web import api

    monkeypatch.setattr(
        api, "team_metrics_payload",
        lambda session: {"mttr_hours": None, "closure_rate_7d": 50.0,
                         "created_7d": 4},
    )
    body = panel_text(client.get("/ui/dashboard-v2/team-metrics").text)
    assert "no closures in 30d" in body
    assert "read failed" not in body


def test_a_measured_zero_hour_mttr_is_printed(client, monkeypatch):
    """The non-boolean arrangement that makes the three-state real.

    Defect: `{% if view.mttr_hours %}`. A mean of 0.0 hours is a measurement
    and the interesting one: every case closed the moment it opened, which
    says the rule is firing on something auto-resolved.

    "0m" alone does not catch that mutation, and a mutation pass is what
    showed it: `_mttr_text(0.0)` is the string "0m", and the else branch
    prints that same string as its explanation, so weakening the gate to
    truthiness renders the identical words through the wrong branch. The
    measured branch is told apart by what only it carries -- the window the
    figure is over -- so that is what this asserts.
    """
    from ion.web import api

    monkeypatch.setattr(
        api, "team_metrics_payload",
        lambda session: {"mttr_hours": 0.0, "closure_rate_7d": 50.0,
                         "created_7d": 4},
    )
    body = panel_text(client.get("/ui/dashboard-v2/team-metrics").text)
    assert "0m" in body
    assert "30d rolling" in body
    assert "no closures in 30d" not in body

    monkeypatch.setattr(
        api, "team_metrics_payload",
        lambda session: {"mttr_hours": None, "closure_rate_7d": 50.0,
                         "created_7d": 4},
    )
    absent = panel_text(client.get("/ui/dashboard-v2/team-metrics").text)
    assert "30d rolling" not in absent, (
        "the unmeasured branch must not claim a window it did not measure, "
        "or the assertion above proves nothing"
    )


def test_a_zero_closure_rate_draws_its_bar_and_a_missing_one_does_not(
    client, monkeypatch
):
    """Defect: `w-[0%]` left standing for an unmeasured rate.

    A rate of 0% is a measurement: nothing opened this week was closed. No
    rate at all happens when nothing was opened, and an empty bar then claims
    a team closed none of the work it was given.
    """
    from ion.web import api

    monkeypatch.setattr(
        api, "team_metrics_payload",
        lambda session: {"mttr_hours": 2.0, "closure_rate_7d": 0.0,
                         "created_7d": 9},
    )
    measured = client.get("/ui/dashboard-v2/team-metrics").text
    assert 'data-ion-style="width:0%"' in measured
    # The percent sign is its own span, so the rendered text is "0 %".
    assert "0 % team-wide" in panel_text(measured)

    monkeypatch.setattr(
        api, "team_metrics_payload",
        lambda session: {"mttr_hours": 2.0, "closure_rate_7d": None,
                         "created_7d": 0},
    )
    absent = client.get("/ui/dashboard-v2/team-metrics").text
    assert "data-ion-style" not in absent
    assert "nothing to divide by" in panel_text(absent)


def test_no_computed_width_is_emitted_as_an_inline_style_attribute():
    """Defect: `style="width:NN%"`.

    ION serves `style-src-attr 'none'`, so the browser drops the declaration
    and the bar silently has no width. The value travels as
    `data-ion-style` and static/js/ion-dynamic-styles.js applies it after
    every swap.
    """
    html = render("metrics", failed=False, view=mod._metrics_view(
        {"mttr_hours": 2.0, "closure_rate_7d": 42.0, "created_7d": 9}
    ))
    assert 'data-ion-style="width:42%"' in html
    assert not re.search(r"\sstyle\s*=", html)


# ---------------------------------------------------------------------------
# My open cases. The count, the status set and the breakdown
# ---------------------------------------------------------------------------


def test_my_open_cases_includes_acknowledged_cases(client, monkeypatch):
    """Defect: `?status=open`, an exact match on AlertCaseStatus.OPEN.

    The client-side `(c.status || '').toLowerCase() !== 'closed'` that
    followed it was dead code, and says what the page meant. So an
    acknowledged case -- one the analyst has picked up and is working --
    vanished from "My open cases", while team-metrics counted the estate's
    open cases as `status != CLOSED`. The same dashboard held two definitions
    of open.
    """
    asked: list[Optional[str]] = []
    from ion.services import case_query_service as cq

    def fake(session, **kw):
        asked.append(kw.get("status"))
        return cases_page([case(status=kw.get("status"))])

    monkeypatch.setattr(cq, "list_cases_page", fake)
    response = client.get("/ui/dashboard-v2/my-cases")

    assert sorted(asked) == ["acknowledged", "open"]
    assert "closed" not in asked
    assert tile(response.text, "kpi-my-cases").endswith("not closed")


def test_the_cases_query_filters_to_the_caller_in_sql(client, monkeypatch):
    """Defect: fetching a hundred of the estate's newest cases and filtering
    them to the caller in the browser.

    Past a hundred open cases the analyst's own count silently fell, because
    their rows were no longer in the page that came back.
    """
    seen: list[dict] = []
    from ion.services import case_query_service as cq

    def fake(session, **kw):
        seen.append(kw)
        return cases_page([case()])

    monkeypatch.setattr(cq, "list_cases_page", fake)
    client.get("/ui/dashboard-v2/my-cases")

    assert seen, "no query was made, so this proves nothing"
    for call in seen:
        assert call["assigned_to_id"] == 42
        assert call["sort"] == "updated_at"
        assert call["order"] == "desc"


def test_the_case_count_is_the_query_total_not_the_rows_returned(
    client, monkeypatch
):
    """Defect: `$('kpi-my-cases').textContent = mine.length`.

    A length of what fitted in one page is not a count. `list_cases_page`
    runs a COUNT over the same filters for exactly this, so the arrangement
    is a page of two rows out of a total of 250.
    """
    from ion.services import case_query_service as cq

    monkeypatch.setattr(
        cq, "list_cases_page",
        only_open([case(), case(id=10)], total=250),
    )
    response = client.get("/ui/dashboard-v2/my-cases")
    assert "My open cases 250" in tile(response.text, "kpi-my-cases")


def test_a_partial_breakdown_says_it_is_partial(client, monkeypatch):
    """Defect: a composition of part of the set drawn as the whole one.

    The bars are counted over the rows that came back, so when the total
    exceeds them the shares are of a sample. The old page never knew the
    difference because it never had a total.
    """
    from ion.services import case_query_service as cq

    monkeypatch.setattr(
        cq, "list_cases_page",
        only_open([case(severity="critical")], total=60),
    )
    breakdown = tile(client.get("/ui/dashboard-v2/my-cases").text, "kpi-my-cases")
    assert "of 1 read" in breakdown


def test_a_complete_breakdown_does_not_claim_to_be_partial(client, monkeypatch):
    """The other half, without which the test above passes on a template that
    always says "partial"."""
    from ion.services import case_query_service as cq

    monkeypatch.setattr(
        cq, "list_cases_page",
        only_open([case(severity="critical")]),
    )
    breakdown = tile(client.get("/ui/dashboard-v2/my-cases").text, "kpi-my-cases")
    assert "read" not in breakdown
    assert "1 crit" in breakdown


def test_cases_with_none_above_medium_is_not_the_same_as_no_cases(
    client, monkeypatch
):
    """Defect: "all clear" printed for both.

    The breakdown only ever listed critical, high and medium, so an analyst
    holding four low-severity cases got the same two words as an analyst
    holding none. One of those shifts has work in it.
    """
    from ion.services import case_query_service as cq

    monkeypatch.setattr(
        cq, "list_cases_page",
        only_open([case(severity="low")]),
    )
    low_only = tile(client.get("/ui/dashboard-v2/my-cases").text, "kpi-my-cases")
    assert "none above medium" in low_only

    monkeypatch.setattr(cq, "list_cases_page", only_open([]))
    empty = tile(client.get("/ui/dashboard-v2/my-cases").text, "kpi-my-cases")
    assert "none assigned" in empty
    assert "none above medium" not in empty


def test_zero_open_cases_is_a_counted_zero_and_not_a_failed_read(
    client, monkeypatch
):
    """Defect: `{% if view.count %}` on the tile.

    An analyst with nothing assigned is the measurement they most want to
    trust, and under truthiness it renders through the branch that says the
    read failed. Found by a mutation pass: every other case test arranges a
    non-empty page or a raising query, so a counted zero was never asserted
    and the gate on it was decorative.
    """
    from ion.services import case_query_service as cq

    monkeypatch.setattr(cq, "list_cases_page", only_open([]))
    tile_text = tile(client.get("/ui/dashboard-v2/my-cases").text, "kpi-my-cases")

    assert "My open cases 0" in tile_text
    assert "assigned to you, not closed" in tile_text
    assert "not counted" not in tile_text
    assert "read failed" not in tile_text


def test_a_case_linked_to_zero_alerts_shows_the_zero(client, monkeypatch):
    """Defect: `if (c.alert_count)`.

    A case with no alerts linked is the one worth looking at: somebody opened
    it by hand, or the link failed. Truthiness hid exactly that row's figure.
    """
    from ion.services import case_query_service as cq

    monkeypatch.setattr(
        cq, "list_cases_page",
        only_open([case(alert_count=0)]),
    )
    assert "0 alerts" in panel_text(client.get("/ui/dashboard-v2/my-cases").text)


def test_a_case_with_no_alert_count_does_not_show_a_zero(client, monkeypatch):
    """What makes the test above non-vacuous: a missing count is not zero."""
    from ion.services import case_query_service as cq

    monkeypatch.setattr(
        cq, "list_cases_page",
        only_open([case(alert_count=None)]),
    )
    body = panel_text(client.get("/ui/dashboard-v2/my-cases").text)
    assert "0 alerts" not in body
    # The row's only alert text is the gated chip, so a count the read did not
    # carry means the word does not appear in the panel at all.
    assert "alert" not in body.lower()


def test_a_case_with_no_timestamps_says_so_rather_than_showing_the_epoch():
    """Defect: `relativeTime(undefined)` returning "", so the row read
    "Updated " with nothing after it, and `new Date(null)` measuring from the
    epoch elsewhere on the page."""
    view = mod._cases_view(
        [cases_page([case(updated_at=None, created_at=None)])]
    )
    html = render("cases", failed=False, view=view)
    body = panel_text(html)
    assert "Update time not recorded" in body
    assert "1970" not in body


# ---------------------------------------------------------------------------
# Handover. Three figures, three `is not none`
# ---------------------------------------------------------------------------


def test_a_handover_report_missing_a_figure_does_not_print_a_zero(
    client, monkeypatch
):
    """Defect: `h.cases?.opened ?? 0`.

    "Zero cases opened this shift" is a sentence an incoming lead acts on.
    The arrangement gives a real zero for one figure and no key at all for
    another, which is what makes `?? 0` and `is not none` disagree.
    """
    from ion.services import shift_handover_service

    monkeypatch.setattr(
        shift_handover_service, "generate_shift_report",
        lambda session, hours: handover_report(
            cases={"closed": 0}, alerts={}
        ),
    )
    body = panel_text(client.get("/ui/dashboard-v2/handover").text)
    assert "opened, not reported" in body
    assert "triaged, not reported" in body
    assert "0 closed" in body


def test_the_handover_window_asked_for_is_the_one_the_page_labels(
    client, monkeypatch
):
    """Defect: the panel saying one window and the query asking for another.

    The page shell labels the panel "Last 8h" and the failure branch says
    "nothing in the last 8h has been measured", both from a constant. If the
    route asked the service for a different window, every figure under that
    label would be of a period the page does not name, and nothing about the
    rendering would look wrong. The window has never been a control, so the
    assertion is that it is the one value and that the label agrees with it.
    """
    from ion.services import shift_handover_service

    asked: list[int] = []

    def fake(session, hours):
        asked.append(hours)
        return handover_report()

    monkeypatch.setattr(shift_handover_service, "generate_shift_report", fake)
    client.get("/ui/dashboard-v2/handover")

    assert asked == [mod.HANDOVER_HOURS]
    assert mod.HANDOVER_HOURS == 8
    assert "Last 8h" in flat(PAGE.read_text(encoding="utf-8"))


def test_a_shift_that_really_did_nothing_prints_three_zeros(client, monkeypatch):
    """Defect: truthiness on any of the three figures.

    The test above arranges a missing key and a single real zero; this
    arranges a real zero for all three, which is the shape that tells
    `is not none` apart from truthiness on each of them independently. A
    mutation pass found `opened` and `triaged` surviving exactly because
    neither was ever arranged as a measured zero: a quiet shift is a finding
    and has to be distinguishable from a report that carried no figure.
    """
    from ion.services import shift_handover_service

    monkeypatch.setattr(
        shift_handover_service, "generate_shift_report",
        lambda session, hours: handover_report(
            cases={"opened": 0, "closed": 0},
            alerts={"total_triaged": 0},
        ),
    )
    body = panel_text(client.get("/ui/dashboard-v2/handover").text)

    assert "0 opened" in body
    assert "0 closed" in body
    assert "0 triaged" in body
    assert "not reported" not in body


def test_every_handover_figure_is_printed_when_it_is_there():
    """Positive control, so the test above cannot pass on a strip that never
    prints a figure at all."""
    view = mod._handover_view(handover_report(), 8)
    body = panel_text(render("handover", failed=False, view=view, hours=8))
    assert "4 opened" in body
    assert "2 closed" in body
    assert "17 triaged" in body
    assert "not reported" not in body


def test_an_unknown_highlight_level_still_renders_its_message():
    """Defect: `LEVEL_CLS[hl.level]` with no fallback, which would drop the
    message rather than the colour. A level added to _build_highlights must
    not silence the finding it carries."""
    view = mod._handover_view(
        handover_report(highlights=[{"level": "urgent", "message": "ransom note found"}]),
        8,
    )
    body = panel_text(render("handover", failed=False, view=view, hours=8))
    assert "ransom note found" in body


# ---------------------------------------------------------------------------
# Escaping. The hand-rolled escHtml is gone and Jinja does it
# ---------------------------------------------------------------------------


SCRIPT = "<script>alert(1)</script>"


def test_jinja_escapes_a_script_tag_in_every_field_the_feed_renders(
    client, monkeypatch
):
    """Defect: trusting `escHtml`, or forgetting it on one field.

    It was applied to five of the alert row's fields and not to
    `mitre_tactic_name` or `mitre_technique_id`, so a tactic name out of the
    index was interpolated raw.
    """
    from ion.web import api

    async def hostile():
        return es_live(alerts=[alert(
            title=SCRIPT, host=SCRIPT, user=SCRIPT, rule_name=SCRIPT,
            mitre_tactic_name=SCRIPT, mitre_technique_id=SCRIPT,
        )])

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", hostile)
    body = client.get("/ui/dashboard-v2/overview").text

    assert SCRIPT not in body
    assert "&lt;script&gt;" in body


def test_jinja_escapes_a_script_tag_in_a_case_title(client, monkeypatch):
    from ion.services import case_query_service as cq

    monkeypatch.setattr(
        cq, "list_cases_page",
        only_open([case(title=SCRIPT, case_number=SCRIPT)]),
    )
    body = client.get("/ui/dashboard-v2/my-cases").text
    assert SCRIPT not in body
    assert "&lt;script&gt;" in body


def test_jinja_escapes_a_script_tag_in_a_handover_highlight(client, monkeypatch):
    from ion.services import shift_handover_service

    monkeypatch.setattr(
        shift_handover_service, "generate_shift_report",
        lambda session, hours: handover_report(
            highlights=[{"level": "info", "message": SCRIPT}]
        ),
    )
    body = client.get("/ui/dashboard-v2/handover").text
    assert SCRIPT not in body
    assert "&lt;script&gt;" in body


def test_an_alert_id_is_escaped_into_its_query_string(client, monkeypatch):
    """Defect: `?id=` built from a raw value.

    `encodeURIComponent` was right in the JavaScript and a port that drops it
    emits an id containing `&` or `"` straight into the attribute.
    """
    from ion.web import api

    async def odd_id():
        return es_live(alerts=[alert(id='a&b"c')])

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", odd_id)
    body = client.get("/ui/dashboard-v2/overview").text
    assert 'href="/alerts?id=a%26b%22c"' in body


def test_an_alert_timestamp_goes_through_the_ts_macro(client, monkeypatch):
    """Defect: a server-formatted timestamp.

    The JavaScript called `hhmmss()` on the viewer's clock. A server knows
    only its own, so formatting the instant here would show an analyst in
    another timezone the wrong time on every row. The macro emits
    `<time datetime>` with a UTC-labelled fallback and
    static/js/local-time.js rewrites the text after load and after each swap.

    Asserted on the rendered element rather than on the template source,
    because an `{{ ts(...) }}` that is never reached renders nothing and a
    source grep cannot tell the difference.
    """
    from ion.web import api

    async def stamped():
        return es_live(alerts=[alert(timestamp="2026-10-12T09:00:00+00:00")])

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", stamped)
    body = panel(client.get("/ui/dashboard-v2/overview").text)

    stamp = re.search(r'<time datetime="([^"]+)"[^>]*data-ts-format="time"', body)
    assert stamp, "the alert row emitted no <time> element"
    assert stamp.group(1).startswith("2026-10-12T09:00:00")
    assert 'data-ts-local="yes"' in body


def test_an_alert_with_no_timestamp_gets_the_fallback_not_the_epoch(
    client, monkeypatch
):
    """Defect: `hhmmss(null)` returning "", which rendered a blank line that
    read as a row with no age rather than a row with no timestamp. A date
    parsed from null would have been worse: 1 January 1970."""
    from ion.web import api

    async def undated():
        return es_live(alerts=[alert(timestamp=None)])

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", undated)
    body = panel_text(client.get("/ui/dashboard-v2/overview").text)

    assert "no time" in body
    assert "age unknown" in body
    assert "1970" not in body


def test_a_naive_stored_timestamp_is_not_relabelled_as_utc(client, monkeypatch):
    """Defect: handing the macro a datetime this module made aware.

    AlertCase stores updated_at and created_at naive, defaulting to the
    database's own `func.now()`, which is UTC on SQLite and the session
    timezone on Postgres, with nothing in the row to say which. `_ts_parts`
    exists to make that call: a zoneless value is marked
    `data-ts-local="no"` and left as stored, because JavaScript parses a
    zoneless ISO string as local time and would convert out of a zone the
    value was never in.

    Stamping UTC on it before the macro sees it defeats that and is worse
    than formatting on the server, because the row then carries an offset it
    was never measured in and looks authoritative. ION runs Postgres in
    production, so this is the deployment that matters.
    """
    from ion.services import case_query_service as cq

    monkeypatch.setattr(
        cq, "list_cases_page",
        only_open([case(updated_at="2026-10-12T08:00:00",
                        created_at="2026-10-11T08:00:00")]),
    )
    body = panel(client.get("/ui/dashboard-v2/my-cases").text)

    assert 'data-ts-local="no"' in body
    assert 'datetime="2026-10-12T08:00:00"' in body
    assert "+00:00" not in body
    assert "Server time" in body


def test_a_timestamp_that_carries_its_zone_is_localised(client, monkeypatch):
    """The other half, without which the test above passes on a page that
    never localises anything. An Elasticsearch alert document stamps an
    offset, so that one is the viewer's to convert."""
    from ion.web import api

    async def stamped():
        return es_live(alerts=[alert(timestamp="2026-10-12T09:00:00+00:00")])

    monkeypatch.setattr(api, "dashboard_elasticsearch_payload", stamped)
    body = panel(client.get("/ui/dashboard-v2/overview").text)

    assert 'data-ts-local="yes"' in body
    assert 'datetime="2026-10-12T09:00:00+00:00"' in body


def test_no_fragment_formats_a_timestamp_itself():
    """The other half: the macro being used somewhere does not stop a second
    place formatting its own. `strftime` and a manual slice are both ways to
    put the server's clock on the page."""
    for path in FRAGMENTS:
        source = strip_comments(path.read_text(encoding="utf-8"))
        assert "strftime" not in source, path.name
        assert "<time" not in source, path.name  # only via the ts macro


def test_the_hand_rolled_escaper_is_gone_from_the_page():
    """Defect: the page keeping its own escaper, which is one more definition
    of what is safe. Comments are stripped first, because this file and the
    page both name `escHtml` in order to explain its removal, and a
    whole-file match would pass on the explanation."""
    source = strip_comments(PAGE.read_text(encoding="utf-8"))
    assert "escHtml" not in source
    assert "replace(/[&<>" not in source


# ---------------------------------------------------------------------------
# The page shell builds no markup, and uses nothing CSP refuses
# ---------------------------------------------------------------------------


def test_the_page_assigns_no_markup_from_javascript():
    """The redesign's `server` column, asserted here rather than trusted.

    Comments are stripped and an assignment is matched rather than the bare
    word, because `hx-swap="innerHTML"` appears on this page by design and
    the comments quote `innerHTML` to explain the removal.
    """
    source = strip_comments(PAGE.read_text(encoding="utf-8"))
    assert not re.search(r"innerHTML\s*\+?=", source)
    assert not re.search(r"outerHTML\s*\+?=", source)
    assert "insertAdjacentHTML" not in source


def test_the_page_uses_no_htmx_feature_that_compiles_a_string():
    """Defect: a dead control that reads as a working one.

    ION serves `script-src 'self' 'nonce-...'` with no `unsafe-eval`, so
    anything htmx hands to `Function()` throws and the feature silently does
    nothing. That is invisible outside a browser console: the markup looks
    right and the server's response is right.
    """
    for path in [PAGE, *FRAGMENTS]:
        source = strip_comments(path.read_text(encoding="utf-8"))
        assert "hx-on" not in source, path.name
        assert "js:" not in source, path.name
        assert not re.search(r'hx-vals="\s*js:', source), path.name
        for trigger in re.findall(r'hx-trigger="([^"]*)"', source):
            assert "[" not in trigger, (path.name, trigger)


def test_no_fragment_emits_an_inline_style_attribute():
    """Defect: `style="width:NN%"`, which `style-src-attr 'none'` drops.

    Checked over the fragments as files rather than over one render, so a
    branch no fixture reaches is covered too.
    """
    for path in [PAGE, *FRAGMENTS]:
        source = strip_comments(path.read_text(encoding="utf-8"))
        assert not re.search(r"<[^>]*\sstyle\s*=", source), path.name


def test_no_fragment_writes_its_own_failure_handler():
    """Defect: a per-page copy of what an expired session means.

    static/js/htmx-errors.js is the one definition, and it is what words a
    403 on the cases region as "this account cannot read it".

    The page is in this loop and not only the fragments. A mutation pass on
    this guard added a listener to the page's own script block and it passed,
    because the fragments carry no script at all: the loop was covering the
    four files that cannot hold the defect and skipping the one that can.
    """
    for path in [PAGE, *FRAGMENTS]:
        source = path.read_text(encoding="utf-8")
        assert "htmx:responseError" not in source, path.name
        assert "htmx:sendError" not in source, path.name
        assert "htmx:timeout" not in source, path.name
        assert "htmx:afterRequest" not in source, path.name


def test_the_retry_control_for_every_region_is_outside_its_swap_target():
    """Defect: a Refresh button inside the region it refreshes.

    A render that says the read failed would remove the control that retries
    it, leaving a reload as the only way out. The page shell declares each
    region's hx-get and each region's Refresh points at that region's target,
    and no fragment declares an hx-get of its own.
    """
    page = strip_comments(PAGE.read_text(encoding="utf-8"))
    for region in REGIONS:
        url = f"/ui/dashboard-v2/{region}"
        assert page.count(f'hx-get="{url}"') == 2, region

    # Counting the two occurrences is not the check: a mutation pass on this
    # guard moved a Refresh button inside the div it targets and the count was
    # still two, so the defect the docstring names went undetected. What makes
    # it a defect is containment, so containment is what this asserts.
    for target in TARGETS:
        # The CONTENTS, not the element. `_element` returns the markup from
        # the open tag onward, and a swap container's own open tag carries
        # the hx-get that loads it, which is the arrangement this test is
        # defending rather than a violation of it. Asserting over the whole
        # element failed on every region for that reason: the guard was
        # reporting its own subject as the defect.
        inside = _element(page, target)
        contents = inside[inside.index(">") + 1:]
        assert "hx-get" not in contents, (
            f"a control inside #{target} would be removed by any render of "
            f"that region, including the render that says the read failed"
        )

    for path in FRAGMENTS:
        source = strip_comments(path.read_text(encoding="utf-8"))
        assert "hx-get" not in source, path.name


def test_no_region_declares_an_hx_include_so_none_can_duplicate_a_parameter():
    """Defect: an inherited `hx-include` appended to a nested request that
    already bakes the same parameter in, which FastAPI then reads from the
    control rather than from the markup.

    This page has no filter, window select or search box: the handover window
    is a constant in the module and has never been a control. So there is
    nothing to include, nothing nested that requests anything, and the
    duplicate is unreachable. Asserted rather than argued, because adding a
    control later is exactly when this stops being true.
    """
    for path in [PAGE, *FRAGMENTS]:
        source = strip_comments(path.read_text(encoding="utf-8"))
        assert "hx-include" not in source, path.name
        assert "hx-disinherit" not in source, path.name


def test_the_page_route_gate_is_not_changed_by_this_conversion():
    """`/` stays `require_page_auth`, which is looser than three of the four
    reads. A page dependency redirects to /login, so it must never reach a
    fragment; the registry guard asserts that separately. This records that
    the page gate is server.py's and was left alone."""
    from ion.web.server import app

    route = next(r for r in app.routes if getattr(r, "path", None) == "/")
    names = []
    stack = list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if dep.call is not None:
            names.append(getattr(dep.call, "__qualname__", ""))
        stack.extend(dep.dependencies)
    assert any("require_page_auth" in n for n in names)


def test_every_fragment_this_module_names_exists():
    """A module without its template is a route that 500s on every request."""
    named = set(re.findall(
        r"""['"](_fragments/[\w./-]+\.html)['"]""",
        Path(mod.__file__).read_text(encoding="utf-8"),
    ))
    assert len(named) == len(REGIONS)
    for name in named:
        assert (TEMPLATES / name).exists(), name
