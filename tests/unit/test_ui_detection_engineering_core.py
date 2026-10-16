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


@pytest.mark.parametrize('payload,state', [({},'failed'),({'spaces':[],'active':'default'},'empty'),({'spaces':[{'space':'a"<b>','rule_count':0}],'active':'a"<b>'},'data')])
def test_space_options_are_safe_and_service_selection_is_preserved(client, monkeypatch, payload, state):
    monkeypatch.setattr(de_tide_api,'tide_de_spaces',lambda:payload)
    response=client.get('/ui/detection-engineering/spaces')
    assert response.status_code == 200
    soup=BeautifulSoup(response.text,'html.parser')
    assert soup.find('b') is None
    if state == 'data':
        option=soup.select_one('option')
        assert option['value']=='a"<b>'
        assert option.has_attr('selected')
        assert option.text=='a"<b> (0)'
    assert client.get('/ui/detection-engineering/spaces',headers={'Accept':'application/json'}).json()['state']==state
