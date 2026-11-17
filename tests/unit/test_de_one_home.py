"""Detection Engineering is one home: the pages it absorbed redirect to their
tab, no licence gate stands in front of it, and per-action permissions still
decide what each person sees."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

ABSORBED = {
    "/de": "requests",
    "/de-proposals": "proposals",
    "/de-quirks": "quirks",
    "/de-bob": "scorecard",
    "/de-oversight": "abuse",
    "/detection-health": "health",
    "/de-metrics": "health",
    "/log-sources": "systems",
}


@pytest.fixture(scope="module")
def app():
    from ion.web.server import app
    return app


@pytest.mark.parametrize("path,sub", sorted(ABSORBED.items()))
def test_each_absorbed_page_redirects_to_its_tab(app, path, sub):
    for method in ("GET", "HEAD"):
        response = TestClient(app).request(method, path, follow_redirects=False)
        assert response.status_code == 302, method
        assert response.headers["location"] == f"/detection-engineering#{sub}"


def test_a_redirect_keeps_the_query_string(app):
    response = TestClient(app).get("/de-proposals?source=bob", follow_redirects=False)
    assert response.headers["location"] == "/detection-engineering?source=bob#proposals"
    legacy = TestClient(app).get("/tuning-proposals", follow_redirects=False)
    assert legacy.headers["location"] == "/detection-engineering?source=bob#proposals"


def test_every_redirect_target_is_a_sub_view_the_page_has(app):
    from pathlib import Path
    import re
    script = (Path(__file__).resolve().parents[2] / "src/ion/web/static/js/detection-engineering.js").read_text(encoding="utf-8")
    known = set(re.findall(r"(\w+):'\w+'", re.search(r"const SUB_TAB = \{(.*?)\};", script, re.S).group(1)))
    assert set(ABSORBED.values()) <= known


def test_the_absorbed_pages_are_gone_from_the_menus():
    from ion.web import nav
    hrefs = {item.href for group in nav.NAV for item in getattr(group, "items", (group,))}
    assert "/detection-engineering" in hrefs
    assert not hrefs & set(ABSORBED), hrefs & set(ABSORBED)


def test_no_route_depends_on_the_de_licence_gate(app):
    from fastapi.routing import APIRoute

    def calls(dependant):
        for dep in dependant.dependencies:
            yield dep.call
            yield from calls(dep)

    gated = [route.path for route in app.routes if isinstance(route, APIRoute)
             for call in calls(route.dependant) if getattr(call, "__module__", "") == "ion.licensing.gating"]
    assert gated == []


class _User:
    username = display_name = "u"
    id = 1
    roles = []

    def __init__(self, permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions

    def has_role(self, role):
        return False


def _page(permissions):
    from ion.web.ui._shared import templates
    request = Request({"type": "http", "method": "GET", "path": "/detection-engineering", "headers": [],
                       "query_string": b"", "app": None})
    return templates.get_template("detection_engineering.html").render(request=request, current_user=_User(permissions))


def test_the_abuse_monitor_renders_only_for_de_verify():
    without = _page({"alert:read", "de:read"})
    assert 'id="de-panel-abuse"' not in without and 'data-subtab="abuse"' not in without
    assert "dx-locked" in without and "de:verify" in without
    holder = _page({"alert:read", "de:read", "de:verify"})
    assert 'id="de-panel-abuse"' in holder and 'data-subtab="abuse"' in holder
    assert 'title="Needs the de:verify permission"' not in holder


def test_the_abuse_route_refuses_without_de_verify_whatever_the_page_shows():
    from fastapi import FastAPI

    from ion.auth.dependencies import get_current_user
    from ion.storage.database import get_db_session
    from ion.web.ui import _detection_engineering_bob as bob

    app = FastAPI()
    app.include_router(bob.router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: _User({"alert:read", "de:read"})
    app.dependency_overrides[get_db_session] = lambda: None
    assert TestClient(app).get("/ui/detection-engineering/bob/abuse").status_code == 403


def _health_client(monkeypatch, report):
    from fastapi import FastAPI

    from ion.auth.dependencies import get_current_user
    from ion.services import rule_health_service as rh
    from ion.storage.database import get_db_session
    from ion.web.ui import _detection_engineering_health as ui

    async def cached(session):
        return report
    monkeypatch.setattr(rh, "cached_rule_health", cached)
    app = FastAPI()
    app.include_router(ui.router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: _User({"alert:read"})
    app.dependency_overrides[get_db_session] = lambda: None
    for route in ui.router.routes:
        for dep in route.dependant.dependencies:
            if dep.call not in (get_db_session, get_current_user):
                app.dependency_overrides[dep.call] = lambda: _User({"alert:read"})
    return TestClient(app)


def _rule(**kw):
    from ion.services import rule_health_service as rh
    base = dict(rule_id="r1", name="Noisy rule", kind="elastic", severity="high", enabled=True, quality=60.0,
                mitre_ids=["T1059"], dest=rh.Destination("elastic", "default"), days=[30] * 14)
    base.update(kw)
    return rh.RuleHealth(**base)


def test_health_groups_tide_rule_monitoring_when_the_tenant_has_it(monkeypatch):
    from ion.services import rule_health_service as rh
    rule = _rule(problems=[rh.tide_problem({"issue": "no_recent_data", "severity": "error", "detail": "No new event for 3 days."})])
    html = _health_client(monkeypatch, rh.RuleHealthReport(state="data", rules=[rule], monitoring="tide")).get(
        "/ui/detection-engineering/health").text
    assert "No recent events in the index pattern" in html and "TIDE Rule Monitoring" in html
    assert "needs TIDE 7" not in html


def test_health_falls_back_to_ion_thresholds_and_says_why(monkeypatch):
    from ion.services import rule_health_service as rh
    rule = _rule(problems=rh.ion_problems([30] * 14, 420, True))
    report = rh.RuleHealthReport(state="data", rules=[rule], monitoring="ion",
                                 notes=["Rule Monitoring needs TIDE 7 (rule_issues is not in this tenant). ION judges alert volume itself until it is."])
    html = _health_client(monkeypatch, report).get("/ui/detection-engineering/health").text
    assert "Over 200 alerts in 14 days" in html and "Rule Monitoring needs TIDE 7" in html
    assert "ION volume checks" in html


def test_a_tide_without_wazuh_assets_reads_as_needing_tide_7_not_as_clean():
    from ion.services import de_systems_service as ds
    from ion.services.tide_service import TableAbsent, TideService

    class _OldTide(TideService):
        def __init__(self):
            self.enabled, self.scope = True, None

        def get_system_platforms(self):
            return [{"id": "s1", "name": "Domain Controllers", "platforms": ["Windows"]}]

        def get_mitre_coverage(self, system_id):
            return {"covered": []}

        def _tenant_rows(self, table, sql):
            return TableAbsent(table)

    report = ds.systems_report(_OldTide(), None)
    system = report.get("s1")
    assert system.vulns is None and system.agents is None and system.cis_score is None
    assert any("needs TIDE 7" in n for n in report.notes)
