"""Detection Engineering > Work: requests, proposals, quirks and the content pack."""
import json

import pytest
from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
from ion.models.bob_tuning_proposal import BobTuningProposalStatus
from ion.models.detection_proposal import DetectionProposalStatus
from ion.models.system_quirk import SystemQuirkStatus
from ion.storage.database import get_db_session

JSON = {'Accept': 'application/json'}
EVERY = {'de:read', 'de:propose', 'de:approve', 'de:verify'}


class FakeUser:
    id = 1
    username = 'reader'

    def __init__(self, permissions):
        self.permissions = set(permissions)

    def has_permission(self, name):
        return name in self.permissions


@pytest.fixture
def make_client():
    from ion.web.ui import _detection_engineering_work as ui

    def build(permissions=EVERY):
        app = FastAPI()
        app.include_router(ui.router, prefix='/ui')
        app.dependency_overrides[get_current_user] = lambda: FakeUser(permissions)
        app.dependency_overrides[get_db_session] = lambda: None
        return TestClient(app)
    return build


def actions(html):
    return {b['data-click-action'] for b in BeautifulSoup(html, 'html.parser').select('[data-click-action]')}


# ── Requests ─────────────────────────────────────

def _requests(monkeypatch, payload):
    from ion.web import de_api
    from ion.web.ui import _detection_engineering_work as ui
    if isinstance(payload, Exception):
        def read(session):
            raise payload
    else:
        def read(session):
            return payload
    monkeypatch.setattr(de_api, 'tuning_requests_payload', read)
    monkeypatch.setattr(ui, '_usernames', lambda session, payload: {5: 'j.okafor'})


REQUEST = {'id': 212, 'rule_name': 'Encoded PowerShell', 'reason': 'noisy', 'details': 'SCCM floods the queue',
           'status': 'open', 'requested_by_id': 5, 'evidence_json': {'fp_alerts_7d': 0},
           'gitlab_issue_iid': 402, 'gitlab_issue_url': 'https://gitlab.example/issues/402',
           'created_at': '2026-11-14T09:00:00'}


@pytest.mark.parametrize('payload,state', [
    (RuntimeError('db down'), 'failed'),
    ({'error': 'refused'}, 'failed'),
    ({'requests': []}, 'empty'),
    ({'requests': [dict(REQUEST, status='closed')]}, 'empty'),
    ({'requests': [REQUEST]}, 'data'),
])
def test_requests_three_states(make_client, monkeypatch, payload, state):
    _requests(monkeypatch, payload)
    client = make_client()
    assert client.get('/ui/detection-engineering/work/requests', headers=JSON).json()['state'] == state
    html = client.get('/ui/detection-engineering/work/requests').text
    count = BeautifulSoup(html, 'html.parser').select_one('#de-count-requests').get_text()
    if state == 'failed':
        assert 'could not be read' in html and 'queue is clear' not in html
        assert count == ''
    elif state == 'empty':
        assert 'queue is clear' in html and count == '0'
    else:
        assert 'REQ-212' in html and 'Too noisy' in html and 'j.okafor' in html and 'GitLab #402' in html
        assert count == '1'


def test_requests_render_a_measured_zero_and_refuse_script_links(make_client, monkeypatch):
    _requests(monkeypatch, {'requests': [dict(REQUEST, gitlab_issue_url='javascript:alert(1)')]})
    soup = BeautifulSoup(make_client().get('/ui/detection-engineering/work/requests').text, 'html.parser')
    assert not soup.select('a[href^="javascript"]')
    row = soup.select_one('tbody tr')
    assert [td.get_text(strip=True) for td in row.select('td')][6] == '0'


def test_request_actions_need_de_propose_and_follow_status(make_client, monkeypatch):
    _requests(monkeypatch, {'requests': [REQUEST, dict(REQUEST, id=213, status='triaged')]})
    html = make_client({'de:read'}).get('/ui/detection-engineering/work/requests').text
    assert not actions(html) - {'deOpenRule'}
    soup = BeautifulSoup(make_client().get('/ui/detection-engineering/work/requests').text, 'html.parser')
    open_row, triaged_row = soup.select('tbody tr')
    assert {b['data-click-action'] for b in open_row.select('.dx-acts button')} == {'dwTriage', 'dwDraftForRequest', 'dwClose'}
    assert {b['data-click-action'] for b in triaged_row.select('.dx-acts button')} == {'dwDraftForRequest', 'dwClose'}
    assert json.loads(open_row.select_one('[data-click-action="dwDraftForRequest"]')['data-args']) == [212, 'Encoded PowerShell']


def test_every_request_status_has_an_action_entry():
    from ion.models.tuning_request import TUNING_REQUEST_STATUSES
    from ion.web.ui._detection_engineering_work import REQUEST_ACTIONS
    assert set(REQUEST_ACTIONS) == set(TUNING_REQUEST_STATUSES)


# ── Proposals ────────────────────────────────────

DETECTION = {'id': 3, 'title': 'Raise 5712 frequency', 'rule_name': 'SSHD brute force', 'status': 'draft',
             'source': 'human', 'change_type': 'threshold', 'suggested_change': 'freq 12 in 120s',
             'expected_fp_reduction': 130, 'expected_hours_reclaimed': 4.5, 'created_by_username': 'j.okafor',
             'created_at': '2026-11-10T10:00:00'}
BOB_TUNING = {'id': 9, 'title': 'Tune Bob for MFA fatigue', 'rule_name': 'MFA fatigue', 'status': 'draft',
              'problem_statement': 'Bob calls these FP', 'created_by_username': 'a.patel', 'evidence_backed': False,
              'created_at': '2026-11-12T10:00:00'}


@pytest.fixture
def proposal_reads(monkeypatch):
    from ion.services import de_bob_proposal_service, de_proposal_service
    seen = {'detection': [], 'bob': 0}
    data = {'detection': [DETECTION, dict(DETECTION, id=2, source='bob', created_by_username=None)],
            'bob': [BOB_TUNING]}

    def detection(session, source=None, **kwargs):
        seen['detection'].append(source)
        if isinstance(data['detection'], Exception):
            raise data['detection']
        return [p for p in data['detection'] if source in (None, 'all') or p['source'] == source]

    def bob(session, status=None, **kwargs):
        seen['bob'] += 1
        if isinstance(data['bob'], Exception):
            raise data['bob']
        return data['bob']
    monkeypatch.setattr(de_proposal_service, 'list_proposals', detection)
    monkeypatch.setattr(de_bob_proposal_service, 'list_proposals', bob)
    return seen, data


def test_bob_tuning_proposals_are_listed_with_source_bob(make_client, proposal_reads):
    view = make_client().get('/ui/detection-engineering/work/proposals', headers=JSON).json()
    assert [(r['kind'], r['source'], r['by']) for r in view['rows']] == [
        ('bob_tuning', 'bob', 'a.patel'), ('detection', 'analyst', 'j.okafor'), ('detection', 'bob', 'Bob')]
    assert view['count'] == 3 and view['bob_count'] == 2


@pytest.mark.parametrize('query,detection_source,reads_bob,wanted', [
    ('', 'all', True, 'all'),
    ('?source=bob', 'bob', True, 'bob'),
    ('?source=analyst', 'human', False, 'analyst'),
    ('?source=human', 'human', False, 'analyst'),
])
def test_source_filter(make_client, proposal_reads, query, detection_source, reads_bob, wanted):
    seen, _ = proposal_reads
    view = make_client().get('/ui/detection-engineering/work/proposals' + query, headers=JSON).json()
    assert seen['detection'] == [detection_source]
    assert bool(seen['bob']) is reads_bob
    assert view['source'] == wanted
    sources = {r['source'] for r in view['rows']}
    assert sources == {'all': {'bob', 'analyst'}, 'bob': {'bob'}, 'analyst': {'analyst'}}[wanted]


def test_unknown_source_is_a_bad_request_not_a_failed_read(make_client, proposal_reads):
    assert make_client().get('/ui/detection-engineering/work/proposals?source=nobody').status_code == 422


def test_one_failed_read_is_named_and_not_counted(make_client, proposal_reads):
    _, data = proposal_reads
    data['detection'] = RuntimeError('db down')
    client = make_client()
    view = client.get('/ui/detection-engineering/work/proposals', headers=JSON).json()
    assert view['state'] == 'data' and view['failed'] == ['detection proposals'] and view['count'] is None
    html = client.get('/ui/detection-engineering/work/proposals').text
    assert 'Detection proposals could not be read' in html and 'Tune Bob for MFA fatigue' in html
    assert BeautifulSoup(html, 'html.parser').select_one('#de-count-proposals').get_text() == ''
    data['bob'] = RuntimeError('db down')
    html = client.get('/ui/detection-engineering/work/proposals').text
    assert client.get('/ui/detection-engineering/work/proposals', headers=JSON).json()['state'] == 'failed'
    assert 'No proposals yet' not in html


def test_no_proposals_is_empty(make_client, proposal_reads):
    _, data = proposal_reads
    data['detection'], data['bob'] = [], []
    html = make_client().get('/ui/detection-engineering/work/proposals').text
    assert 'No proposals yet' in html


def test_effect_quotes_the_measurement_not_the_forecast_or_the_uneven_drop(make_client, proposal_reads):
    _, data = proposal_reads
    measured = dict(DETECTION, id=4, status='applied', applied_at='2026-10-01T00:00:00', outcome={
        'drop_pct': 99.0, 'comparable': {'sufficient_observation': True, 'drop_pct': 0, 'before_count': 10,
                                         'after_count': 10, 'window_days_exact': 30}})
    legacy = dict(DETECTION, id=5, status='applied', applied_at='2026-10-01T00:00:00', outcome={'drop_pct': 80.0})
    data['detection'], data['bob'] = [measured, legacy, DETECTION], []
    rows = make_client().get('/ui/detection-engineering/work/proposals', headers=JSON).json()['rows']
    effects = {r['id']: (r['effect'] or {}).get('text') for r in rows}
    assert effects[4] == '−0% FP (measured)'
    assert '80' not in (effects[5] or '') and '99' not in effects[4]
    assert effects[3] is None
    assert {r['id']: r['forecast'] for r in rows}[3] == '−130 FP (est.) · 4.5h'


def test_proposal_controls_follow_permission_and_status(make_client, proposal_reads):
    _, data = proposal_reads
    applied_bob = dict(BOB_TUNING, id=10, status='approved')
    unmeasurable = dict(DETECTION, id=6, status='applied', applied_at=None)
    data['detection'] = [DETECTION, unmeasurable]
    data['bob'] = [BOB_TUNING, applied_bob]
    reader = make_client({'de:read'}).get('/ui/detection-engineering/work/proposals').text
    assert not actions(reader) - {'deOpenRule', 'dwProposalSource'}
    assert 'dw-edit-dialog' not in reader
    proposer = make_client({'de:read', 'de:propose'}).get('/ui/detection-engineering/work/proposals').text
    assert {'dpEdit', 'dpDecide'} <= actions(proposer) and not actions(proposer) & {'bbApprove', 'bbRevert', 'dpMeasure'}
    assert 'dw-edit-dialog' in proposer and 'dw-decide-dialog' in proposer
    approver = make_client({'de:read', 'de:approve'}).get('/ui/detection-engineering/work/proposals').text
    assert {'bbApprove', 'bbReject', 'bbRevert'} <= actions(approver) and 'dpEdit' not in actions(approver)
    soup = BeautifulSoup(approver, 'html.parser')
    assert json.loads(soup.select_one('[data-click-action="bbApprove"]')['data-args']) == [9, False]


def test_every_proposal_status_has_an_action_entry():
    from ion.web.ui._detection_engineering_work import BOB_ACTIONS, DETECTION_ACTIONS
    assert set(DETECTION_ACTIONS) == {s.value for s in DetectionProposalStatus}
    assert set(BOB_ACTIONS) == {s.value for s in BobTuningProposalStatus}


# ── Quirks ───────────────────────────────────────

QUIRK = {'id': 7, 'title': 'DC clock drift', 'annotation': 'Hyper-V migration', 'status': 'active', 'expired': True,
         'review_date': '2026-11-01T00:00:00', 'scope_rules': ['golden ticket'], 'scope_hosts': ['dc01'],
         'raised_by_username': 'm.lindqvist', 'verified_by_username': 'a.patel'}


@pytest.mark.parametrize('result,state', [(RuntimeError('db'), 'failed'), ([], 'empty'), ([QUIRK], 'data')])
def test_quirks_three_states(make_client, monkeypatch, result, state):
    from ion.services import de_quirk_service

    def read(session, status=None, **kwargs):
        if isinstance(result, Exception):
            raise result
        return result
    monkeypatch.setattr(de_quirk_service, 'list_quirks', read)
    client = make_client()
    assert client.get('/ui/detection-engineering/work/quirks', headers=JSON).json()['state'] == state
    html = client.get('/ui/detection-engineering/work/quirks').text
    assert ('could not be read' in html) is (state == 'failed')
    assert ('No quirks recorded' in html) is (state == 'empty')
    if state == 'data':
        assert 'rule:golden ticket' in html and 'host:dc01' in html and 'lapsed' in html


def test_quirk_review_dates_are_stated_in_utc(make_client, monkeypatch):
    from ion.services import de_quirk_service
    monkeypatch.setattr(de_quirk_service, 'list_quirks', lambda session, status=None, **k: [QUIRK])
    client = make_client()
    row = client.get('/ui/detection-engineering/work/quirks', headers=JSON).json()['rows'][0]
    assert row['review_date'] == '2026-11-01T00:00:00+00:00'
    time = BeautifulSoup(client.get('/ui/detection-engineering/work/quirks').text, 'html.parser').select_one('time')
    assert time['data-ts-local'] == 'yes'


def test_quirk_controls_follow_permission(make_client, monkeypatch):
    from ion.services import de_quirk_service
    pending = dict(QUIRK, id=8, status='pending', expired=False)
    monkeypatch.setattr(de_quirk_service, 'list_quirks', lambda session, status=None, **k: [pending, QUIRK])
    reader = make_client({'de:read'}).get('/ui/detection-engineering/work/quirks').text
    assert not actions(reader) and 'dw-raise-dialog' not in reader
    proposer = make_client({'de:read', 'de:propose'}).get('/ui/detection-engineering/work/quirks').text
    assert actions(proposer) == {'dwOpenRaise', 'dwCloseDialog', 'dwSubmitRaise'}
    verifier = make_client({'de:read', 'de:verify'}).get('/ui/detection-engineering/work/quirks').text
    assert actions(verifier) == {'dwVerifyQuirk', 'dwRevertQuirk'}


def test_every_quirk_status_has_an_action_entry():
    from ion.web.ui._detection_engineering_work import QUIRK_ACTIONS
    assert set(QUIRK_ACTIONS) == {s.value for s in SystemQuirkStatus}


# ── Content pack and gates ───────────────────────

def test_content_pack_import_needs_de_propose(make_client):
    reader = make_client({'de:read'}).get('/ui/detection-engineering/work/content-pack').text
    assert 'dwExportPack' in reader and 'dwPickPack' not in reader and 'dw-pack-file' not in reader
    proposer = make_client({'de:read', 'de:propose'}).get('/ui/detection-engineering/work/content-pack').text
    assert 'dwPickPack' in proposer and 'dw-pack-file' in proposer


@pytest.mark.parametrize('path', ['requests', 'proposals', 'quirks', 'content-pack'])
def test_every_work_route_needs_de_read(make_client, path):
    assert make_client({'alert:read'}).get('/ui/detection-engineering/work/' + path).status_code == 403
