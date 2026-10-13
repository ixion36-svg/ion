from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    from ion.web.ui import _observables_analysis as ui
    from ion.storage.database import get_db_session
    app = FastAPI()
    app.include_router(ui.router, prefix='/ui')
    for route in ui.router.routes:
        for dependency in route.dependant.dependencies:
            if dependency.call is not get_db_session:
                app.dependency_overrides[dependency.call] = lambda: SimpleNamespace()
    app.dependency_overrides[get_db_session] = lambda: None
    service = SimpleNamespace(get_by_id=lambda ident: SimpleNamespace(type='ip', value='<value>', first_seen=None, last_seen=None, sighting_count=0))
    monkeypatch.setattr(ui, 'ObservableService', lambda session: service)
    return TestClient(app), service


@pytest.mark.parametrize('payload,state', [(None, 'failed'), ({}, 'failed'), ({'nodes': [], 'edges': []}, 'empty'), ({'nodes': [{'id': 1}], 'edges': []}, 'data')])
def test_graph_states(client, payload, state):
    c, service = client
    service.get_relationship_graph = lambda **kwargs: payload
    assert c.get('/ui/observables/graph', headers={'Accept': 'application/json'}).json()['state'] == state


@pytest.mark.parametrize('panel,method', [('patterns', 'detect_patterns'), ('1/timeline', 'get_timeline')])
@pytest.mark.parametrize('payload,state', [(None, 'failed'), ({}, 'failed'), ([], 'empty'), ([{'observables': []}], 'data')])
def test_collection_states(client, panel, method, payload, state):
    c, service = client
    setattr(service, method, lambda *args, **kwargs: payload)
    assert c.get('/ui/observables/' + panel, headers={'Accept': 'application/json'}).json()['state'] == state


@pytest.mark.parametrize('payload,state', [(None, 'failed'), ([], 'failed'), ({}, 'empty'), ({'2026-10-13': 0}, 'data')])
def test_heatmap_states(client, payload, state):
    c, service = client
    service.get_activity_heatmap = lambda *args, **kwargs: payload
    assert c.get('/ui/observables/1/heatmap', headers={'Accept': 'application/json'}).json()['state'] == state


@pytest.mark.parametrize('score,expected', [(None, '—'), (0, '0'), (75, '75')])
def test_timeline_score_and_escaping(client, score, expected):
    c, service = client
    service.get_timeline = lambda *a, **k: [{'type': 'enrichment', 'score': score, 'source': '<script>bad</script>'}]
    html = c.get('/ui/observables/1/timeline').text
    assert f'Score: {expected}' in html
    assert '<script>' not in html


@pytest.mark.parametrize('panel,method', [('graph', 'get_relationship_graph'), ('patterns', 'detect_patterns'), ('1/timeline', 'get_timeline'), ('1/heatmap', 'get_activity_heatmap')])
def test_failure_is_not_empty(client, panel, method):
    c, service = client
    def fail(*a, **k):
        raise RuntimeError('private detail')
    setattr(service, method, fail)
    html = c.get('/ui/observables/' + panel).text
    assert 'Failed to load' in html
    assert 'private detail' not in html


def test_info_missing_zero(client):
    c, _ = client
    html = c.get('/ui/observables/1/timeline-info').text
    assert 'Sightings: 0' in html
    assert '&lt;value&gt;' in html


def test_graph_json_is_safe(client):
    from bs4 import BeautifulSoup
    import json
    c, service = client
    service.get_relationship_graph = lambda **k: {'nodes': [{'id': 1, 'label': "</script>'\""}], 'edges': []}
    soup = BeautifulSoup(c.get('/ui/observables/graph').text, 'html.parser')
    assert json.loads(soup.select_one('[data-graph]')['data-graph'])['nodes'][0]['label'] == "</script>'\""
    assert soup.find('script') is None


def test_every_fragment_requires_observable_read():
    from ion.web.ui import _observables_analysis as ui
    for route in ui.router.routes:
        dependency = next(d.call for d in route.dependant.dependencies if d.call.__name__ != 'get_db_session')
        closure = dict(zip(dependency.__code__.co_freevars, [cell.cell_contents for cell in dependency.__closure__]))
        assert 'observable:read' in closure.values()


@pytest.mark.parametrize('observables', [None, {}, 'unknown'])
def test_patterns_malformed_nested_rows_fail(client, observables):
    c, service = client
    service.detect_patterns = lambda **k: [{'observables': observables}]
    assert 'Failed to load patterns' in c.get('/ui/observables/patterns').text


@pytest.mark.parametrize('count,expected', [(None, '—'), (0, '0'), (8, '8')])
def test_pattern_numbers_and_arguments(client, count, expected):
    from bs4 import BeautifulSoup
    import json
    c, service = client
    service.detect_patterns = lambda **k: [{'occurrence_count': count, 'observables': [{'id': 5, 'type': 'ip', 'value': "<script>quote'\"", 'threat_level': 'unknown'}]}]
    soup = BeautifulSoup(c.get('/ui/observables/patterns').text, 'html.parser')
    assert soup.select_one('.pattern-count').text == expected
    assert soup.find('script') is None
    assert [json.loads(e['data-args']) for e in soup.select('[data-args]')] == [[5], [5]]


@pytest.mark.parametrize('panel', ['1/timeline', '1/heatmap', '1/timeline-info'])
def test_missing_observable_is_failed_read(client, panel):
    c, service = client
    service.get_by_id = lambda ident: None
    assert 'Failed to load' in c.get('/ui/observables/' + panel).text


@pytest.mark.parametrize('panel', ['graph', 'patterns', '1/timeline', '1/heatmap', '1/timeline-info'])
def test_real_permission_denial(panel, monkeypatch):
    from ion.web.ui import _observables_analysis as ui
    from ion.auth import dependencies
    from ion.storage.database import get_db_session
    app = FastAPI()
    app.include_router(ui.router, prefix='/ui')
    app.dependency_overrides[get_db_session] = lambda: None
    app.dependency_overrides[dependencies.get_current_user] = lambda: SimpleNamespace(username='viewer', has_permission=lambda p: False)
    monkeypatch.setattr(dependencies, 'audit_refusal', lambda *a, **k: None)
    assert TestClient(app).get('/ui/observables/' + panel).status_code == 403
