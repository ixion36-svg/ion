import importlib
from types import SimpleNamespace

from bs4 import BeautifulSoup
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
import pytest

from ion.web import de_tide_api
from ion.storage.database import get_db_session


@pytest.fixture
def client():
    try:
        ui = importlib.import_module('ion.web.ui._detection_engineering_core')
    except ModuleNotFoundError as error:
        if error.name != 'ion.web.ui._detection_engineering_core':
            raise
        ui = SimpleNamespace(router=APIRouter())
    app = FastAPI()
    app.include_router(ui.router, prefix='/ui')
    for route in ui.router.routes:
        for dependency in route.dependant.dependencies:
            if dependency.call is not get_db_session:
                app.dependency_overrides[dependency.call] = lambda: SimpleNamespace(has_permission=lambda permission: True)
    app.dependency_overrides[get_db_session] = lambda: None
    return TestClient(app)
@pytest.mark.parametrize('payload,state', [
    ({}, 'failed'),
    ({'destinations': None, 'active': ''}, 'failed'),
    ({'destinations': [], 'active': ''}, 'empty'),
    ({'destinations': [{'key': 'siem|a"<b>', 'siem_id': 'siem', 'space': 'a"<b>', 'kind': 'wazuh', 'rule_count': 0}], 'active': 'siem|a"<b>'}, 'data'),
])
def test_destination_options_are_safe_and_service_selection_is_preserved(client, monkeypatch, payload, state):
    monkeypatch.setattr(de_tide_api, 'tide_de_destinations', lambda: payload)
    response = client.get('/ui/detection-engineering/destinations')
    assert response.status_code == 200
    soup = BeautifulSoup(response.text, 'html.parser')
    assert soup.find('b') is None
    options = soup.select('option')
    if state == 'failed':
        assert [o.text for o in options] == ['Destinations unavailable']
    else:
        assert options[0]['value'] == '' and options[0].text.startswith('All destinations')
    if state == 'data':
        assert options[1]['value'] == 'siem|a"<b>'
        assert options[1].has_attr('selected') and not options[0].has_attr('selected')
        assert options[1].text == 'Wazuh · siem / a"<b> (0)'
    assert client.get('/ui/detection-engineering/destinations', headers={'Accept': 'application/json'}).json()['state'] == state


def test_all_destinations_is_selected_and_totals_every_destination(client, monkeypatch):
    listed = [{'key': 'e|default', 'siem_id': 'e', 'space': 'default', 'kind': 'elastic', 'rule_count': 2},
              {'key': 'w|*', 'siem_id': 'w', 'space': '*', 'kind': 'wazuh', 'rule_count': 3}]
    monkeypatch.setattr(de_tide_api, 'tide_de_destinations', lambda: {'destinations': listed, 'active': ''})
    options = BeautifulSoup(client.get('/ui/detection-engineering/destinations').text, 'html.parser').select('option')
    assert options[0].text == 'All destinations (5)' and options[0].has_attr('selected')


def test_a_space_only_setting_stays_visible_as_the_selection(client, monkeypatch):
    """A saved space with no SIEM matches no listed destination's key; the
    picker must still show it as the active choice, not fall back to All."""
    listed = [{'key': 'e|default', 'siem_id': 'e', 'space': 'default', 'kind': 'elastic', 'rule_count': 2}]
    monkeypatch.setattr(de_tide_api, 'tide_de_destinations', lambda: {'destinations': listed, 'active': '|default'})
    selected = BeautifulSoup(client.get('/ui/detection-engineering/destinations').text, 'html.parser').select('option[selected]')
    assert [(o['value'], o.text) for o in selected] == [('|default', 'default on any SIEM (saved setting)')]


