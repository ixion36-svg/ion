from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    from ion.web.ui import _training_plans as ui
    from ion.storage.database import get_db_session
    app = FastAPI()
    app.include_router(ui.router, prefix='/ui')
    for route in ui.router.routes:
        for dependency in route.dependant.dependencies:
            if dependency.call is not get_db_session:
                app.dependency_overrides[dependency.call] = lambda: SimpleNamespace(id=7)
    app.dependency_overrides[get_db_session] = lambda: None
    return TestClient(app), ui


@pytest.mark.parametrize('payload,state,message', [
    ({}, 'failed', 'Failed to load training plan'),
    ({'plans': []}, 'failed', 'Failed to load training plan'),
    ({'plans': [{'id': 1}]}, 'failed', 'Failed to load training plan'),
    ({'plans': [{'id': 1, 'items': []}]}, 'empty', 'No certifications added yet'),
    ({'plans': [{'id': 1, 'items': [{'id': 2, 'cert_name': 'A < B', 'price': 0}]}]}, 'data', 'A &lt; B'),
])
def test_items_states(client, monkeypatch, payload, state, message):
    c, ui = client
    monkeypatch.setattr(ui.skills_api, 'get_training_plans', lambda **kwargs: payload)
    response = c.get('/ui/training/plans/1/items')
    assert response.status_code == 200
    assert message in response.text
    assert c.get('/ui/training/plans/1/items', headers={'Accept': 'application/json'}).json()['state'] == state


def test_item_missing_values_and_safe_actions(client, monkeypatch):
    from bs4 import BeautifulSoup
    import json
    c, ui = client
    item = {'id': 2, 'status': 'planned"quoted', 'cert_name': '<script>bad</script>'}
    monkeypatch.setattr(ui.skills_api, 'get_training_plans', lambda **kwargs: {'plans': [{'id': 1, 'items': [item]}]})
    soup = BeautifulSoup(c.get('/ui/training/plans/1/items').text, 'html.parser')
    assert soup.select_one('.tp-item-price').text == 'Unknown'
    assert soup.select_one('.tp-item-provider').text == 'Unknown'
    assert soup.select_one('.tp-item-funding').text == 'Unknown'
    assert json.loads(soup.select_one('[data-click-action="tpToggleComplete"]')['data-args']) == [1, 2, 'planned"quoted']
    assert soup.find('script') is None


@pytest.mark.parametrize('payload,state,message', [
    ({}, 'failed', 'Failed to load forecast data'),
    ({'forecasts': []}, 'empty', 'No personnel have active training plans yet'),
    ({'forecasts': [{'display_name': 'Alice'}]}, 'data', 'Alice'),
])
def test_forecast_states(client, monkeypatch, payload, state, message):
    c, ui = client
    monkeypatch.setattr(ui.skills_api, 'get_training_forecast', lambda **kwargs: payload)
    response = c.get('/ui/training/forecast')
    assert message in response.text
    assert c.get('/ui/training/forecast', headers={'Accept': 'application/json'}).json()['state'] == state


@pytest.mark.parametrize('zero', [None, 0])
def test_forecast_missing_or_zero_fields(client, monkeypatch, zero):
    from bs4 import BeautifulSoup
    c, ui = client
    f = {key: zero for key in ('item_count', 'completed_count', 'total_cost', 'company_cost', 'self_cost')}
    payload = {'forecasts': [f], 'totals': {k: zero for k in ('total', 'company', 'self', 'split', 'tbd')}, 'plan_count': zero,
               'by_employment_type': {'cs': {k: zero for k in ('headcount', 'certs', 'total', 'company', 'self', 'split', 'tbd')}}}
    monkeypatch.setattr(ui.skills_api, 'get_training_forecast', lambda **kwargs: payload)
    soup = BeautifulSoup(c.get('/ui/training/forecast').text, 'html.parser')
    costs = soup.select('.fc-cost')
    assert len(costs) == 3
    assert {el.text for el in costs} == ({'Unknown'} if zero is None else {'£0'})
    values = soup.select('.tp-summary-value')
    assert len(values) == 7
    assert all(('Unknown' in el.text) == (zero is None) for el in values)


def test_read_exceptions_render_failure(client, monkeypatch):
    c, ui = client
    def fail(**kwargs):
        raise RuntimeError('backend unavailable')
    monkeypatch.setattr(ui.skills_api, 'get_training_plans', fail)
    monkeypatch.setattr(ui.skills_api, 'get_training_forecast', fail)
    assert 'Failed to load training plan' in c.get('/ui/training/plans/1/items').text
    assert 'Failed to load forecast data' in c.get('/ui/training/forecast').text


@pytest.mark.parametrize('key,selector', [
    ('cert_name', '.tp-item-name'), ('provider', '.tp-item-provider'),
    ('price', '.tp-item-price'), ('difficulty', '.tp-item-difficulty'),
    ('funding_type', '.tp-item-funding'), ('status', '.tp-item-status'),
])
def test_each_item_field_missing(client, monkeypatch, key, selector):
    from bs4 import BeautifulSoup
    c, ui = client
    item = {'id': 2, 'cert_name': 'Test', 'provider': 'Provider', 'price': 0,
            'difficulty': 'beginner', 'funding_type': 'company', 'status': 'planned'}
    item.pop(key)
    monkeypatch.setattr(ui.skills_api, 'get_training_plans', lambda **kwargs: {'plans': [{'id': 1, 'items': [item]}]})
    soup = BeautifulSoup(c.get('/ui/training/plans/1/items').text, 'html.parser')
    assert soup.select_one(selector).text == 'Unknown'


@pytest.mark.parametrize('key,index', [('total_cost', 0), ('company_cost', 1), ('self_cost', 2)])
def test_each_forecast_cost_missing(client, monkeypatch, key, index):
    from bs4 import BeautifulSoup
    c, ui = client
    forecast = {'total_cost': 0, 'company_cost': 0, 'self_cost': 0}
    forecast.pop(key)
    monkeypatch.setattr(ui.skills_api, 'get_training_forecast', lambda **kwargs: {'forecasts': [forecast]})
    soup = BeautifulSoup(c.get('/ui/training/forecast').text, 'html.parser')
    assert [el.text for el in soup.select('.fc-cost')] == ['Unknown' if i == index else '£0' for i in range(3)]


@pytest.mark.parametrize('payload', [
    {'forecasts': [None]}, {'forecasts': ['wrong']},
    {'forecasts': [{'item_count': 'five', 'completed_count': 1}]},
    {'forecasts': [{'item_count': 1, 'completed_count': float('inf')}]},
    {'forecasts': [{}], 'totals': {'company': 'oops', 'split': 0, 'tbd': 0}},
    {'forecasts': [{}], 'by_employment_type': {'cs': None}},
    {'forecasts': [{}], 'by_employment_type': {'cs': {'total': 'oops'}}},
])
def test_malformed_forecast_is_unavailable(client, monkeypatch, payload):
    c, ui = client
    monkeypatch.setattr(ui.skills_api, 'get_training_forecast', lambda **kwargs: payload)
    response = c.get('/ui/training/forecast')
    assert response.status_code == 200
    assert 'Failed to load forecast data' in response.text
    model = c.get('/ui/training/forecast', headers={'Accept': 'application/json'}).json()
    assert model['state'] == 'failed'


@pytest.mark.parametrize('item', [None, 'wrong', {'price': 'free'}, {'price': float('nan')}])
def test_malformed_plan_items_are_unavailable(client, monkeypatch, item):
    c, ui = client
    monkeypatch.setattr(ui.skills_api, 'get_training_plans', lambda **kwargs: {'plans': [{'id': 1, 'items': [item]}]})
    response = c.get('/ui/training/plans/1/items')
    assert response.status_code == 200
    assert 'Failed to load training plan' in response.text
