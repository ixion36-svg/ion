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


@pytest.mark.parametrize('payload,state,text', [
    (None, 'failed', 'Failed to load posture'),
    ({}, 'failed', 'Failed to load posture'),
    ({'enabled': False}, 'unconfigured', 'TIDE not configured'),
    ({'enabled': True, 'total_rules': 0, 'severity': {}, 'quality': {}}, 'empty', 'No detection rules'),
    ({'enabled': True, 'total_rules': 3}, 'data', 'Total Rules'),
])
def test_posture_read_outcomes(client, monkeypatch, payload, state, text):
    monkeypatch.setattr(de_tide_api, 'tide_de_posture', lambda **kwargs: payload)
    monkeypatch.setattr(de_tide_api, 'tide_de_disabled_critical', lambda **kwargs: [])
    response = client.get('/ui/detection-engineering/posture')
    assert response.status_code == 200
    assert text in response.text
    assert client.get('/ui/detection-engineering/posture', headers={'Accept':'application/json'}).json()['state'] == state


@pytest.mark.parametrize('field', ['total_rules','enabled_rules','disabled_rules','covered_techniques','unmapped_rules','total_systems'])
@pytest.mark.parametrize('value', [None, 0, 6])
def test_posture_each_figure_keeps_zero_and_unknown(client, monkeypatch, field, value):
    payload = {'enabled':True, 'total_rules':8, field:value}
    monkeypatch.setattr(de_tide_api, 'tide_de_posture', lambda **kwargs: payload)
    monkeypatch.setattr(de_tide_api, 'tide_de_disabled_critical', lambda **kwargs: [])
    response = client.get('/ui/detection-engineering/posture')
    assert response.status_code == 200
    cell = BeautifulSoup(response.text,'html.parser').select_one('[data-field="' + field + '"]')
    assert cell is not None
    assert cell.get_text(strip=True) == ('Unknown' if value is None else str(value))


def test_posture_failed_secondary_read_preserves_primary_stats(client, monkeypatch):
    monkeypatch.setattr(de_tide_api, 'tide_de_posture', lambda **kwargs: {'enabled':True,'total_rules':0})
    def failed(**kwargs):
        raise RuntimeError('private backend detail')
    monkeypatch.setattr(de_tide_api, 'tide_de_disabled_critical', failed)
    response = client.get('/ui/detection-engineering/posture')
    assert response.status_code == 200
    soup = BeautifulSoup(response.text, 'html.parser')
    assert soup.select_one('[data-field="total_rules"]').text == '0'
    assert 'Disabled critical/high rules unavailable' in response.text
    assert 'private backend detail' not in response.text


@pytest.mark.parametrize('payload,state,text', [
    (None,'failed','Failed to load gaps'),
    ({},'failed','Failed to load gaps'),
    ({'enabled':False},'unconfigured','TIDE not configured'),
    ({'enabled':True,'total_blind_spots':0,'blind_spots_by_tactic':{},'unmapped_rules':[],'quick_wins':[],'systems_coverage':[]},'empty','No detection gaps'),
    ({'enabled':True,'total_blind_spots':1,'blind_spots_by_tactic':{'initial-access':[{'id':'T0001','name':'<quoted>'}]},'unmapped_rules':[],'quick_wins':[],'systems_coverage':[]},'data','T0001'),
])
def test_gaps_read_outcomes(client, monkeypatch, payload, state, text):
    monkeypatch.setattr(de_tide_api, 'tide_de_gaps', lambda **kwargs: payload)
    response = client.get('/ui/detection-engineering/gaps')
    assert response.status_code == 200
    assert text in response.text
    assert client.get('/ui/detection-engineering/gaps',headers={'Accept':'application/json'}).json()['state'] == state
    assert BeautifulSoup(response.text,'html.parser').find('quoted') is None


@pytest.mark.parametrize('missing', ['unmapped_rules','quick_wins','systems_coverage','blind_spots_by_tactic'])
def test_gaps_missing_region_does_not_claim_none_found(client, monkeypatch, missing):
    payload={'enabled':True,'total_blind_spots':0,'blind_spots_by_tactic':{},'unmapped_rules':[],'quick_wins':[],'systems_coverage':[]}
    del payload[missing]
    monkeypatch.setattr(de_tide_api, 'tide_de_gaps', lambda **kwargs: payload)
    response = client.get('/ui/detection-engineering/gaps',headers={'Accept':'application/json'})
    assert response.status_code == 200
    model = response.json()
    assert model[missing] is None
    assert model['state'] != 'empty'


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


@pytest.mark.parametrize('route,panel', [('posture', 'tide_de_posture'), ('gaps', 'tide_de_gaps')])
def test_a_refused_read_shows_tides_reason_not_an_empty_panel(client, monkeypatch, route, panel):
    failure = {'kind': 'auth_rejected', 'status': 401, 'detail': 'Invalid or missing API key.',
               'message': 'TIDE rejected the API key. Keys made with AUTH_DISABLED belong to dev-user-001.'}
    monkeypatch.setattr(de_tide_api, panel, lambda **kwargs: {'enabled': True, 'failure': failure})
    monkeypatch.setattr(de_tide_api, 'tide_de_disabled_critical', lambda **kwargs: [])
    response = client.get('/ui/detection-engineering/' + route)
    assert 'dev-user-001' in response.text
    assert 'TIDE said: Invalid or missing API key.' in response.text
    assert 'No detection' not in response.text
    assert client.get('/ui/detection-engineering/' + route, headers={'Accept': 'application/json'}).json()['state'] == 'failed'


def test_a_reasonless_failure_is_still_failed(client, monkeypatch):
    monkeypatch.setattr(de_tide_api, 'tide_de_posture', lambda **kwargs: {'enabled': True, 'failure': None})
    monkeypatch.setattr(de_tide_api, 'tide_de_disabled_critical', lambda **kwargs: [])
    assert 'Failed to load posture' in client.get('/ui/detection-engineering/posture').text


def test_unscored_rules_get_their_own_band_and_kinds_are_named(client, monkeypatch):
    quality = {'excellent': 1, 'good': 1, 'fair': 0, 'poor': 0, 'unscored': 3, 'scale': 'percent', 'avg_quality': 76}
    payload = {'enabled': True, 'total_rules': 5, 'quality': quality,
               'rules_by_kind': {'elastic': {'total': 2, 'enabled': 1}, 'wazuh': {'total': 3, 'enabled': 3}}}
    monkeypatch.setattr(de_tide_api, 'tide_de_posture', lambda **kwargs: payload)
    monkeypatch.setattr(de_tide_api, 'tide_de_disabled_critical', lambda **kwargs: [])
    text = client.get('/ui/detection-engineering/posture').text
    assert 'Unscored (mostly Wazuh): <strong>3</strong>' in text
    assert 'Poor (&lt;25%): <strong>0</strong>' in text
    assert 'Elastic 2 · Wazuh 3' in text


@pytest.mark.parametrize('scale,label', [('percent', 'Excellent (80%+)'), ('points', 'Excellent (30+)'), (None, 'Excellent (30+)')])
def test_quality_labels_follow_the_scale_tide_scores_on(client, monkeypatch, scale, label):
    """TIDE 5.1+ scores in percent and ION bands at 80/50/25; the legend
    must say so rather than name the old points bands."""
    quality = {'excellent': 1, 'good': 1, 'fair': 1, 'poor': 1, 'avg_quality': 46.3, **({'scale': scale} if scale else {})}
    monkeypatch.setattr(de_tide_api, 'tide_de_posture', lambda **kwargs: {'enabled': True, 'total_rules': 4, 'quality': quality})
    monkeypatch.setattr(de_tide_api, 'tide_de_disabled_critical', lambda **kwargs: [])
    assert label in client.get('/ui/detection-engineering/posture').text
