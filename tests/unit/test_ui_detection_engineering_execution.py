from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    from ion.web.ui import _detection_engineering_execution as ui
    from ion.storage.database import get_db_session
    app = FastAPI()
    app.include_router(ui.router, prefix='/ui')
    for route in ui.router.routes:
        for dependency in route.dependant.dependencies:
            if dependency.call is not get_db_session:
                app.dependency_overrides[dependency.call] = lambda: SimpleNamespace(id=1)
    app.dependency_overrides[get_db_session] = lambda: None
    return TestClient(app), ui


@pytest.mark.parametrize('payload,state', [({}, 'failed'), ({'enabled': False, 'error': 'Refused'}, 'failed'),
    ({'enabled': True, 'actors': []}, 'empty'), ({'enabled': True, 'actors': [{'id': 'a', 'name': '<actor>'}]}, 'data')])
def test_actor_read_states(client, monkeypatch, payload, state):
    c, ui = client
    async def read(**kwargs):
        return payload
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_actor_readiness', read)
    response = c.get('/ui/detection-engineering/readiness/actors', headers={'Accept': 'application/json'})
    assert response.status_code == 200
    assert response.json()['state'] == state
    html = c.get('/ui/detection-engineering/readiness/actors').text
    if state == 'data':
        assert '&lt;actor&gt;' in html
        assert 'Unknown' in html
    elif state == 'failed':
        assert 'No threat actors found' not in html


@pytest.mark.parametrize('summary', [None, {}, {'total_alerts': 0, 'status': {'open': 0}}])
def test_execution_missing_zero(client, monkeypatch, summary):
    c, ui = client
    async def read(**kwargs):
        return {'enabled': True, 'summary': summary, 'timeline': [], 'top_firing': [], 'noisy_rules': [], 'silent_rules': []}
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_execution', read)
    data = c.get('/ui/detection-engineering/execution', headers={'Accept': 'application/json'}).json()
    assert data['state'] == ('failed' if summary is None else 'empty' if summary.get('total_alerts') == 0 else 'data')
    html = c.get('/ui/detection-engineering/execution').text
    assert 'No firing rules' in html if summary is not None else 'Failed to load' in html
    if summary == {}:
        assert 'Unknown' in html


def test_system_assessment_preserves_inputs_and_escapes_actions(client, monkeypatch):
    import json
    from bs4 import BeautifulSoup
    c, ui = client
    seen = []
    async def read(req, session):
        seen.append(req)
        return {'enabled': True, 'actor': {'name': '<A>'}, 'coverage_matrix': [], 'readiness_pct': 0,
                'covered_count': 0, 'gap_count': 0, 'total_ttps': 0}
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_system_readiness', read)
    response = c.post('/ui/detection-engineering/readiness/system', data={'actor_id': 'a"b', 'actor_type': 'threat_actor', 'system_id': 's', 'generate_ai': True})
    assert response.status_code == 200
    soup = BeautifulSoup(response.text, 'html.parser')
    assert json.loads(soup.select_one('[data-click-action="deDownloadPdf"]')['data-args']) == ['a"b', 'threat_actor']
    assert '&lt;A&gt;' in response.text
    assert '0%' in response.text
    assert seen[0].system_id == 's'
    assert seen[0].generate_ai is False


@pytest.mark.parametrize('payload', [{}, {'enabled': False, 'error': 'Refused'}, {'enabled': True, 'error': 'Failed', 'summary': {}}])
def test_execution_refusals_are_not_empty(client, monkeypatch, payload):
    c, ui = client
    async def read(**kwargs):
        return payload
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_execution', read)
    assert c.get('/ui/detection-engineering/execution', headers={'Accept': 'application/json'}).json()['state'] == 'failed'
    assert 'No firing rules' not in c.get('/ui/detection-engineering/execution').text


def test_execution_charts_and_missing_lists(client, monkeypatch):
    from bs4 import BeautifulSoup
    c, ui = client
    async def read(**kwargs):
        return {'enabled': True, 'summary': {'total_alerts': 0}, 'timeline': [{'timestamp': '<time>', 'count': 10}],
                'severity_timeline': [{'timestamp': 'T', 'critical': 4, 'low': 2}],
                'top_firing': [{'rule_name': '<rule>', 'alert_count': 0, 'close_rate': 0, 'in_tide': True, 'tide_severity': 'critical'}]}
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_execution', read)
    response = c.get('/ui/detection-engineering/execution')
    assert response.status_code == 200
    soup = BeautifulSoup(response.text, 'html.parser')
    assert len(soup.select('.de-vol-chart')) == 2
    assert 'height:100.0%' in soup.select_one('.de-vol-bar')['data-ion-style']
    assert soup.select_one('.de-rate-val').text == '0%'
    assert 'Rules unavailable' in response.text
    assert '&lt;rule&gt;' in response.text
    assert '&lt;time&gt;' in response.text
    assert not soup.select('[style]')


@pytest.mark.parametrize('zero', [None, 0])
def test_actor_missing_zero_and_actions(client, monkeypatch, zero):
    import json
    from bs4 import BeautifulSoup
    c, ui = client
    actor = dict.fromkeys(('readiness_pct', 'covered_count', 'total_ttps', 'gap_count'), zero)
    actor.update(id='a"b', name='Actor', entity_type='intrusion_set', covered=[], gaps=[])
    async def read(**kwargs):
        return {'enabled': True, 'actors': [actor]}
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_actor_readiness', read)
    soup = BeautifulSoup(c.get('/ui/detection-engineering/readiness/actors').text, 'html.parser')
    assert soup.select_one('.de-actor-gauge-val').get_text(strip=True) == ('Unknown' if zero is None else '0%')
    assert json.loads(soup.select_one('[data-click-action="deGenerateReport"]')['data-args']) == ['a"b', 'intrusion_set', '$event']
    assert soup.find(id='de-sysreadiness-a"b') is not None


@pytest.mark.parametrize('systems', [None, [], [{'id': 's', 'name': '<System>', 'classification': 'C'}]])
def test_readiness_shell(client, monkeypatch, systems):
    c, ui = client
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_systems', lambda **kwargs: systems)
    html = c.get('/ui/detection-engineering/readiness').text
    assert 'All Systems (Global)' in html
    if systems is None:
        assert 'Could not load systems' in html
    elif systems:
        assert '&lt;System&gt; (C)' in html


@pytest.mark.parametrize('payload', [{}, {'enabled': False, 'error': 'Not configured'}, {'enabled': True, 'actor': {}, 'coverage_matrix': None}])
def test_system_failure(client, monkeypatch, payload):
    c, ui = client
    async def read(**kwargs):
        return payload
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_system_readiness', read)
    response = c.post('/ui/detection-engineering/readiness/system', data={'actor_id': 'a'})
    assert response.status_code == 200
    assert 'role="alert"' in response.text
    assert 'No techniques recorded' not in response.text


@pytest.mark.parametrize('key,value', [('timeline',[None]), ('timeline',[{'count':None}]), ('timeline',[{}]),
    ('timeline',[{'count':'bad'}]), ('timeline',[{'count':True}]), ('timeline',[{'count':float('inf')}]),
    ('severity_timeline',[None]), ('severity_timeline',[{}]), ('severity_timeline',[{'critical':None}]),
    ('severity_timeline',[{'critical':'bad'}]), ('severity_timeline',[{'critical':True}]),
    ('severity_timeline',[{'critical':float('nan')}])])
def test_chart_unavailable_values(client, monkeypatch, key, value):
    c, ui = client
    async def read(**kwargs):
        return {'enabled': True, 'summary': {'total_alerts': 1}, 'timeline': [], 'severity_timeline': [], key: value}
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_execution', read)
    response = c.get('/ui/detection-engineering/execution')
    assert response.status_code == 200
    assert 'unavailable' in response.text.lower() or 'Unknown' in response.text
    assert 'nan%' not in response.text
    assert 'inf%' not in response.text
    assert c.get('/ui/detection-engineering/execution', headers={'Accept':'application/json'}).status_code == 200


def test_zero_execution_empty_with_measured_stats(client, monkeypatch):
    from bs4 import BeautifulSoup
    c, ui = client
    async def read(**kwargs):
        return {'enabled':True, 'summary':{'total_alerts':0}, 'timeline':[{'count':0}],
                'severity_timeline':[{'critical':0,'high':0,'medium':0,'low':0}]}
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_execution', read)
    assert c.get('/ui/detection-engineering/execution', headers={'Accept':'application/json'}).json()['state'] == 'empty'
    html = c.get('/ui/detection-engineering/execution').text
    assert 'No alerts in this time range' in html
    assert BeautifulSoup(html,'html.parser').select_one('.de-stat-val').get_text(strip=True) == '0'
    assert 'critical: 0' in html


@pytest.mark.parametrize('payload', [[None], [{}], [{'id':None,'name':'System'}]])
def test_readiness_unusable_systems(client, monkeypatch, payload):
    c, ui = client
    monkeypatch.setattr(ui.de_tide_api, 'tide_de_systems', lambda **kwargs: payload)
    response=c.get('/ui/detection-engineering/readiness')
    assert response.status_code == 200
    assert 'Could not load systems' in response.text
