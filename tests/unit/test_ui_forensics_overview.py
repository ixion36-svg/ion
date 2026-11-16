from types import SimpleNamespace
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    from ion.web.ui import _forensics_overview as ui
    from ion.storage.database import get_db_session
    app = FastAPI()
    app.include_router(ui.router, prefix='/ui')
    app.dependency_overrides[get_db_session] = lambda: None
    app.dependency_overrides[ui.PERMISSION] = lambda: SimpleNamespace(has_permission=lambda p: p == 'forensic:read')
    monkeypatch.setattr(ui.forensics_api, 'get_enums', lambda **k: {'investigation_types': ['malware_analysis'], 'evidence_types': [], 'custody_actions': [], 'case_statuses': []})
    monkeypatch.setattr(ui.forensics_api, 'list_playbooks', lambda **k: [])
    return TestClient(app), ui


@pytest.mark.parametrize('payload,state', [(None,'failed'), ({},'failed'), ([], 'empty'), ([{'id':1,'title':'test','case_number':'FR-1'}], 'data')])
def test_cases_states(client, monkeypatch, payload, state):
    c, ui = client
    monkeypatch.setattr(ui.forensics_api, 'list_cases', lambda **k: payload)
    response = c.get('/ui/forensics/overview', headers={'Accept':'application/json'})
    assert response.status_code == 200
    assert response.json()['state'] == state


@pytest.mark.parametrize('payload,state,total', [(None,'failed',None), ({},'failed',None), ([], 'empty',0), ([{}], 'data',1)])
def test_overdue_states(client, monkeypatch, payload, state, total):
    c, ui = client
    monkeypatch.setattr(ui.forensics_api, 'get_overdue_cases', lambda **k: payload)
    response = c.get('/ui/forensics/overdue', headers={'Accept':'application/json'})
    assert response.json() == {'state':state, 'total':total}


def test_user_read_gap_withholds_options_without_reading_users(client, monkeypatch):
    c, ui = client
    def forbidden(*a, **k):
        pytest.fail('user list called without user:read')
    monkeypatch.setattr(ui, 'users_list_payload', forbidden)
    response = c.get('/ui/forensics/options')
    assert response.status_code == 200
    assert 'Analyst options withheld' in response.text
    assert 'disabled' in response.text
    model = c.get('/ui/forensics/options', headers={'Accept':'application/json'}).json()
    assert model['users_state'] == 'withheld' and model['users'] is None
    assert model['can_create'] is False


@pytest.mark.parametrize('payload,state', [(None,'failed'), ({},'failed'), ([], 'empty'), ([{'id':1,'username':'private<name>'}], 'data')])
def test_authorized_user_options_states(client, monkeypatch, payload, state):
    c, ui = client
    c.app.dependency_overrides[ui.PERMISSION] = lambda: SimpleNamespace(has_permission=lambda p: True)
    monkeypatch.setattr(ui, 'users_list_payload', lambda *a, **k: payload)
    model = c.get('/ui/forensics/options', headers={'Accept':'application/json'}).json()
    assert model['users_state'] == state
    if state == 'data':
        assert 'private&lt;name&gt;' in c.get('/ui/forensics/options').text


@pytest.mark.parametrize('field', ['evidence_count','step_count','steps_completed','is_locked','status'])
@pytest.mark.parametrize('value', [None,0])
def test_unknown_metrics_and_progress(client, monkeypatch, field, value):
    c, ui = client
    case = {'id':1,'status':'intake','evidence_count':0,'step_count':0,'steps_completed':0,'is_locked':False, field:value}
    monkeypatch.setattr(ui.forensics_api, 'list_cases', lambda **k:[case])
    model = c.get('/ui/forensics/overview', headers={'Accept':'application/json'}).json()
    if field == 'evidence_count': assert model['metrics']['evidence'] == value
    if field == 'is_locked' and value is None: assert model['metrics']['locked'] is None
    if field == 'status': assert model['metrics']['intake'] is None
    if field in ['step_count','steps_completed'] and value is None: assert model['cases'][0]['progress'] is None


def test_overview_filters_search_and_safe_actions(client, monkeypatch):
    from bs4 import BeautifulSoup
    import json
    c, ui = client
    calls=[]
    def cases(**kwargs):
        calls.append(kwargs)
        return [{'id':7,'title':'<script>match</script>','case_number':'FR-7'}, {'id':8,'title':'other'}]
    monkeypatch.setattr(ui.forensics_api, 'list_cases', cases)
    response = c.get('/ui/forensics/overview?status=intake&priority=high&investigation_type=other&search=match')
    assert calls[0]['status'] == 'intake' and calls[0]['priority'] == 'high' and calls[0]['investigation_type'] == 'other'
    soup = BeautifulSoup(response.text, 'html.parser')
    assert soup.find('script') is None
    assert all(json.loads(el['data-args']) == [7] for el in soup.select('[data-args]'))
    assert 'other' not in soup.select_one('tr').get_text()


@pytest.mark.parametrize('panel,method',[('overview','list_cases'),('overdue','get_overdue_cases')])
def test_service_errors_are_visible(client, monkeypatch, panel, method):
    c, ui = client
    def failed(**k): raise RuntimeError('private')
    monkeypatch.setattr(ui.forensics_api,method,failed)
    html = c.get('/ui/forensics/' + panel).text
    assert 'Failed to load' in html and 'private' not in html


@pytest.mark.parametrize('case,expected', [
    ({'status':'analysis','sla_analysis_due':'2000-01-01T00:00:00','sla_analysis_met':'1999-12-31T23:00:00'}, 'on_track'),
    ({'status':'analysis','sla_analysis_due':'2000-01-01T00:00:00','sla_analysis_met':None}, 'breached'),
    ({'status':'analysis','sla_analysis_due':'2000-01-01T00:00:00'}, 'unknown'),
    ({'status':'closed'}, 'met'),
])
def test_sla_real_model_timestamps(client, monkeypatch, case, expected):
    c, ui = client
    monkeypatch.setattr(ui.forensics_api,'list_cases',lambda **k:[{'id':1, **case}])
    model = c.get('/ui/forensics/overview',headers={'Accept':'application/json'}).json()
    assert model['cases'][0]['sla'] == expected


def test_sla_at_risk_with_real_pending_shape(client, monkeypatch):
    from datetime import datetime, timedelta, timezone
    c, ui = client
    now = datetime.now(timezone.utc)
    case = {'id':1,'status':'analysis','created_at':(now-timedelta(hours=9)).isoformat(),
            'sla_analysis_due':(now+timedelta(hours=1)).isoformat(),'sla_analysis_met':None}
    monkeypatch.setattr(ui.forensics_api,'list_cases',lambda **k:[case])
    assert c.get('/ui/forensics/overview',headers={'Accept':'application/json'}).json()['cases'][0]['sla'] == 'at_risk'
