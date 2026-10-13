from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from ion.web.ui import _detection_engineering_catalogue as ui
    from ion.storage.database import get_db_session
    app = FastAPI()
    app.include_router(ui.router, prefix='/ui')
    for route in ui.router.routes:
        for dep in route.dependant.dependencies:
            if dep.call is not get_db_session:
                app.dependency_overrides[dep.call] = lambda: SimpleNamespace(has_permission=lambda p: True)
    app.dependency_overrides[get_db_session] = lambda: None
    return TestClient(app), ui


@pytest.mark.parametrize('payload,state', [(None, 'failed'), ({}, 'failed'), ({'tactics': [], 'techniques': []}, 'empty'), ({'tactics': [{'id': 'D', 'name': 'Defend'}], 'techniques': []}, 'data')])
def test_d3fend_states(client, monkeypatch, payload, state):
    c, ui = client
    monkeypatch.setattr(ui, 'get_d3fend_coverage', lambda: payload)
    r = c.get('/ui/detection-engineering/d3fend', headers={'Accept': 'application/json'})
    assert r.status_code == 200
    assert r.json()['state'] == state


@pytest.mark.parametrize('payload,state', [(None, 'failed'), ({}, 'failed'), ({'vulnerabilities': []}, 'empty'), ({'vulnerabilities': [{'id': 1, 'title': 'A < B'}]}, 'data')])
def test_vulns_states(client, monkeypatch, payload, state):
    c, ui = client
    monkeypatch.setattr(ui.vulnerability_service, 'coverage_overview', lambda session: payload)
    assert c.get('/ui/detection-engineering/vulns', headers={'Accept': 'application/json'}).json()['state'] == state






@pytest.mark.parametrize('zero', [None, 0])
def test_missing_and_zero_numbers(client, monkeypatch, zero):
    from bs4 import BeautifulSoup
    c, ui = client
    monkeypatch.setattr(ui.vulnerability_service, 'coverage_overview', lambda session: {'vulnerabilities': [{'id': 1, 'title': '<script>x</script>', 'cvss_score': zero}], 'summary': {k: zero for k in ('total', 'covered', 'partial', 'blind')}})
    soup = BeautifulSoup(c.get('/ui/detection-engineering/vulns').text, 'html.parser')
    assert {x.text.strip() for x in soup.select('.de-stat-val')} == ({'—'} if zero is None else {'0'})
    assert soup.select_one('.de-cvss').text == ('—' if zero is None else '0')
    assert soup.find('script') is None




@pytest.mark.parametrize('panel', ['d3fend', 'vulns'])
def test_service_failure(client, monkeypatch, panel):
    c, ui = client
    def fail(*args):
        raise RuntimeError('sensitive failure')
    target, name = {'d3fend': (ui, 'get_d3fend_coverage'), 'emulation': (ui.emulation_service, 'list_plans'), 'vulns': (ui.vulnerability_service, 'coverage_overview')}[panel]
    monkeypatch.setattr(target, name, fail)
    response = c.get('/ui/detection-engineering/' + panel)
    assert 'Failed to load' in response.text
    assert 'sensitive failure' not in response.text


@pytest.mark.parametrize('zero', [None, 0])
def test_d3fend_numbers(client, monkeypatch, zero):
    from bs4 import BeautifulSoup
    c, ui = client
    payload = {'summary': {k: zero for k in ('overall_pct', 'fully_covered', 'partial', 'blind', 'total_techniques')}, 'tactics': [{'id': 'D', 'name': '<Defense>', 'coverage_pct': zero, 'covered_count': zero, 'technique_count': zero}], 'techniques': [{'id': 'D1', 'tactic': 'D', 'name': 'Counter', 'coverage_pct': zero, 'covered_attacks': zero, 'total_attacks': zero}]}
    monkeypatch.setattr(ui, 'get_d3fend_coverage', lambda: payload)
    soup = BeautifulSoup(c.get('/ui/detection-engineering/d3fend').text, 'html.parser')
    assert [x.text.strip() for x in soup.select('.de-stat-val')] == (['—'] * 5 if zero is None else ['0%', '0', '0', '0', '0'])
    assert bool(soup.find('progress')) == (zero is not None)
    assert soup.find('defense') is None






def test_permissions_have_no_licence_dependency(client):
    from fastapi.routing import APIRoute
    from ion.licensing.gating import require_de_module
    _, ui = client
    for route in ui.router.routes:
        assert isinstance(route, APIRoute)
        assert route.response_class.__name__ == 'HTMLResponse'
        assert all(dep.call is not require_de_module for dep in route.dependant.dependencies)
        assert any('alert:read' in (cell.cell_contents for cell in (dep.call.__closure__ or ())) for dep in route.dependant.dependencies if dep.call.__closure__)
