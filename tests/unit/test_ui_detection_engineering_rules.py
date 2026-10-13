from types import SimpleNamespace

import pytest
from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from ion.web.ui import _detection_engineering_rules as ui
    from ion.storage.database import get_db_session
    app = FastAPI()
    app.include_router(ui.router, prefix='/ui')
    for route in ui.router.routes:
        for dependency in route.dependant.dependencies:
            app.dependency_overrides[dependency.call] = lambda: SimpleNamespace(id=7)
    app.dependency_overrides[get_db_session] = lambda: None
    return TestClient(app), ui


@pytest.mark.parametrize('panel,method,empty,data', [
    ('killchains', 'tide_de_use_cases', [], [{'name': 'A < B', 'steps': []}]),
    ('rules', 'tide_de_rules', {'rows': [], 'total': 0}, {'rows': [{'name': 'A < B'}], 'total': 1}),
])
@pytest.mark.parametrize('outcome', ['failed', 'empty', 'data', 'exception'])
def test_outcomes(client, monkeypatch, panel, method, empty, data, outcome):
    c, ui = client
    def result(**kwargs):
        if outcome == 'exception':
            raise RuntimeError('private backend error')
        return {'failed': None, 'empty': empty, 'data': data}[outcome]
    async def async_result(**kwargs):
        return result(**kwargs)
    monkeypatch.setattr(ui.de_tide_api, method, async_result if panel == 'progression' else result)
    url = '/ui/detection-engineering/' + panel
    response = c.get(url)
    assert response.status_code == 200
    state = c.get(url, headers={'Accept': 'application/json'}).json()['state']
    assert state == ('failed' if outcome == 'exception' else outcome)
    assert 'private backend error' not in response.text
    if outcome == 'data':
        assert 'A &lt; B' in response.text


@pytest.mark.parametrize('value', [0, None])
@pytest.mark.parametrize('field', ['quality_score', 'enabled', 'severity', 'name', 'mitre_ids'])
def test_rule_missing_and_zero(client, monkeypatch, field, value):
    c, ui = client
    row = {'name': 'Rule', 'severity': 'high', 'enabled': True, 'quality_score': 50, 'mitre_ids': ['T1003']}
    row[field] = value
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_rules', lambda **kw: {'rows': [row], 'total': 1})
    soup = BeautifulSoup(c.get('/ui/detection-engineering/rules').text, 'html.parser')
    cell = soup.select_one('[data-field="' + field + '"]')
    if value is None:
        assert 'Unavailable' in cell.text
    elif field == 'quality_score':
        assert cell.text.strip() == '0'
    elif field == 'enabled':
        assert cell.text.strip() == 'Disabled'


def test_rule_filters(client, monkeypatch):
    c, ui = client
    calls = []
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_rules', lambda **kw: calls.append(kw) or {'rows': [], 'total': 0})
    c.get('/ui/detection-engineering/rules?search=a%26b&severity=high&enabled=0&offset=50&limit=50')
    assert calls == [dict(search='a&b', severity='high', enabled='0', offset=50, limit=50)]




@pytest.mark.parametrize('coverage,text', [
    ({'T1003': {'rule_count': 4, 'enabled_rules': 2}}, '2 enabled'),
    ({'T1003': {'rule_count': 4, 'enabled_rules': 0}}, '4 rules (0 enabled)'),
    ({'T1003': {'rule_count': 0, 'enabled_rules': 0}}, 'No rules'),
    ({'T1003': {'rule_count': 0}}, 'Coverage unavailable'),
    ({'T1003': {'enabled_rules': 0}}, 'Coverage unavailable'),
    ({}, 'Coverage unavailable'),
    (None, 'Coverage unavailable'),
])
def test_killchain_coverage(client, monkeypatch, coverage, text):
    c, ui = client
    step = {'order': 0, 'name': '<name>', 'techniques': ['T1003'], 'tactic': '<tactic>', 'required_rule': '<rule>'}
    payload = [{'name': '<pb>', 'description': '<desc>', 'steps': [step], 'technique_coverage': coverage}]
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_use_cases', lambda **kw: payload)
    response = c.get('/ui/detection-engineering/killchains').text
    assert text in response
    for field in ('name', 'tactic', 'rule', 'pb', 'desc'):
        assert '&lt;' + field + '&gt;' in response
    assert 'coverage_state' not in step


@pytest.mark.parametrize('techniques,text', [(None, 'Techniques unavailable'), ([], 'No techniques linked')])
def test_killchain_techniques(client, monkeypatch, techniques, text):
    c, ui = client
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_use_cases', lambda **kw: [{'steps': [{'techniques': techniques}]}])
    assert text in c.get('/ui/detection-engineering/killchains').text






def test_permissions_without_licence_gate(client):
    c, ui = client
    from ion.licensing.gating import require_de_module
    assert all(require_de_module != dep.call for route in ui.router.routes for dep in route.dependant.dependencies)
    c.app.dependency_overrides.clear()
    assert c.get('/ui/detection-engineering/rules').status_code in (401, 403)
