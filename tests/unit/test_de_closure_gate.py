"""ION's per-rule closure outcomes stay behind security:read on the one
Detection Engineering home, as Detection Health kept them.

The page itself needs only alert:read. A reader without security:read gets
the Overview, Rules, rule drawer and system detail with no closure figure in
the markup or the JSON model, a lock where the figures would be, and no
Health panel at all. A holder sees every figure.
"""
from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.services import de_systems_service as ds
from ion.services import rule_health_service as rh
from ion.services.rule_outcome_service import OUTCOMES, RuleKey, RuleOutcome
from ion.storage.database import get_db_session
from ion.web import de_tide_api
from ion.web.ui import _detection_engineering_health as health_ui
from ion.web.ui import _detection_engineering_overview as overview_ui
from ion.web.ui.detection_engineering import router

LOCK = "ION closure outcomes need the security:read permission"
#: Figures only ION's closures can produce: 113 FP of 137 closed, 82.5%.
FIGURES = ("137", "113", "82.5", "82%", "83%", "CASE-4242")
READER = {"alert:read", "case:read"}
HOLDER = READER | {"security:read"}


class _User:
    username = display_name = "u"
    id = 1
    roles = []

    def __init__(self, permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


def _outcome():
    counts = dict.fromkeys(OUTCOMES, 0)
    counts.update(true_positive=11, false_positive=113, benign_true_positive=7, other=6)
    return RuleOutcome(key=RuleKey(rule_id="r-loud"), rule_name="Encoded shell", outcomes=counts)


def _report():
    rule = rh.RuleHealth(
        rule_id="r-loud", name="Encoded shell", kind="elastic", severity="high", enabled=True, quality=60.0,
        mitre_ids=["T1059"], dest=rh.Destination("elastic", "default"), days=[3] * 14,
        outcome=_outcome(), noisy=True,
        problems=[rh.tide_problem({"issue": "no_recent_data", "severity": "error", "detail": "No new event for days."})],
    )
    return rh.RuleHealthReport(state="data", rules=[rule], monitoring="tide", alerts_from="tide",
                               closures={"tp": 11, "fp": 113, "benign": 7, "other": 6, "closed": 137})


@pytest.fixture
def report(monkeypatch):
    shared = _report()

    async def cached(session):
        return shared
    monkeypatch.setattr(rh, "cached_rule_health", cached)
    monkeypatch.setattr(rh, "recent_closures", lambda session, rule_id, name: [
        {"case": "CASE-4242", "closed_at": None, "reason": "false_positive", "by": "analyst"}])
    posture = {"enabled": True, "total_rules": 1, "enabled_rules": 1, "disabled_rules": 0, "unmapped_rules": 0,
               "covered_techniques": 1, "total_techniques": 10, "total_systems": 0}
    monkeypatch.setattr(de_tide_api, "tide_de_posture", lambda **kw: posture)
    monkeypatch.setattr(de_tide_api, "tide_de_disabled_critical", lambda **kw: [])
    monkeypatch.setattr(de_tide_api, "tide_de_gaps", lambda **kw: {"enabled": True})
    monkeypatch.setattr(de_tide_api, "tide_de_use_cases", lambda **kw: [])
    monkeypatch.setattr(overview_ui, "_overview_reads", lambda session: (
        overview_ui.posture_view(session), overview_ui.gaps_view(session), ds.SystemsReport(state="data"), None, 0))
    monkeypatch.setattr(health_ui, "_tide_url", lambda: None)
    return shared


def _client(permissions):
    app = FastAPI()
    app.include_router(router, prefix="/ui")
    app.dependency_overrides[get_current_user] = lambda: _User(permissions)
    app.dependency_overrides[get_db_session] = lambda: None
    return TestClient(app)


PANELS = {
    "overview": "/ui/detection-engineering/overview",
    "rules": "/ui/detection-engineering/rules",
    "drawer": "/ui/detection-engineering/rules/drawer?key=r-loud|elastic|default",
}


def _absent(body):
    return [figure for figure in FIGURES if figure in body]


@pytest.mark.parametrize("panel", sorted(PANELS))
def test_without_security_read_no_closure_figure_reaches_the_markup(report, panel):
    response = _client(READER).get(PANELS[panel])
    assert response.status_code == 200
    body = response.text
    assert _absent(body) == [], panel
    assert 'class="dx-fp' not in body and 'class="dx-out"' not in body and "dx-ministats" not in body
    assert "Mostly closed as false positive" not in body
    assert "dx-locked" in body and "security:read" in body
    assert LOCK in body or "need the security:read permission" in body


@pytest.mark.parametrize("panel", ["overview", "rules", "drawer"])
def test_without_security_read_the_json_model_carries_no_closure_figure(report, panel):
    response = _client(READER).get(PANELS[panel], headers={"Accept": "application/json"})
    assert response.status_code == 200, panel
    model = response.json()
    assert _absent(json.dumps(model, default=str)) == [], panel
    assert model.get("closures") is None and model.get("fp_rate") is None and model.get("history") is None
    for rule in model.get("rules") or [model.get("rule")] if "rule" in model or "rules" in model else []:
        assert rule["closures"] is None


def test_the_overview_tile_and_rules_link_skip_health_for_a_reader(report):
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(_client(READER).get(PANELS["overview"]).text, "html.parser")
    assert soup.select_one('[data-field="fp_rate"] .dx-lock') is not None
    assert "noisy" not in soup.select_one('[data-field="needs_attention"]').parent.get_text()
    links = [b["data-args"] for b in soup.select(".dx-attn-h button")]
    assert links == ['["rules"]']


def test_the_health_fragment_refuses_without_security_read(report):
    for accept in ("text/html", "application/json"):
        response = _client(READER).get("/ui/detection-engineering/health", headers={"Accept": accept})
        assert response.status_code == 403
        assert _absent(response.text) == []


def test_the_page_locks_the_health_tab_without_security_read():
    from starlette.requests import Request

    from ion.web.ui._shared import templates

    def page(permissions):
        request = Request({"type": "http", "method": "GET", "path": "/detection-engineering", "headers": [],
                           "query_string": b"", "app": None})
        return templates.get_template("detection_engineering.html").render(request=request, current_user=_User(permissions))

    reader = page(READER | {"de:verify"})
    assert 'id="de-panel-health"' not in reader and 'data-subtab="health"' not in reader
    assert 'title="Needs the security:read permission"' in reader
    holder = page(HOLDER | {"de:verify"})
    assert 'id="de-panel-health"' in holder and 'data-subtab="health"' in holder
    assert "security:read" not in holder


def test_the_system_detail_does_not_say_mostly_fp_for_a_reader(report, monkeypatch):
    from ion.web.ui import _detection_engineering_systems as systems_ui

    report.rules[0].problems = []
    system = ds.SystemProfile(id="s1", name="Domain Controllers", platforms=["Windows"], covered_ids=set())
    monkeypatch.setattr(systems_ui, "_register", lambda session: [])
    monkeypatch.setattr(systems_ui, "_systems", lambda session, registry: ds.SystemsReport(state="data", systems=[system]))
    monkeypatch.setattr(ds, "applicable_techniques", lambda platforms: {"T1059"})
    path = "/ui/detection-engineering/systems/s1"
    holder = _client(HOLDER).get(path, headers={"Accept": "application/json"}).json()
    reader = _client(READER).get(path, headers={"Accept": "application/json"}).json()
    assert [g["why"] for g in holder["gaps"]] == ["mostly FP"]
    assert [g["why"] for g in reader["gaps"]] == ["rule not applied here"]


def test_a_security_read_holder_sees_every_figure_and_a_reader_first_does_not_take_them(report):
    _client(READER).get(PANELS["rules"])
    client = _client(HOLDER)
    rules = client.get(PANELS["rules"]).text
    assert "n=137" in rules and "dx-locked" not in rules
    drawer = client.get(PANELS["drawer"]).text
    assert "CASE-4242" in drawer and "<b>113</b>" in drawer and "dx-locked" not in drawer
    overview = client.get(PANELS["overview"]).text
    assert "113 of 137" in overview and "Mostly closed as false positive" in overview and LOCK not in overview
    health = client.get("/ui/detection-engineering/health")
    assert health.status_code == 200 and "82%" in health.text and "113 of 137" in health.text
    assert report.rules[0].outcome is not None and report.closures["closed"] == 137
