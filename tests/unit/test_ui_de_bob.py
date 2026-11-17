"""Detection Engineering > Bob: scorecard, disagreements and the abuse monitor."""
from datetime import datetime, timezone

import pytest
from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ion.auth.dependencies import get_current_user
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
    from ion.web.ui import _detection_engineering_bob as ui

    def build(permissions=EVERY):
        app = FastAPI()
        app.include_router(ui.router, prefix='/ui')
        app.dependency_overrides[get_current_user] = lambda: FakeUser(permissions)
        app.dependency_overrides[get_db_session] = lambda: None
        return TestClient(app)
    return build


def _returns(value):
    def read(*args, **kwargs):
        if isinstance(value, Exception):
            raise value
        return value
    return read


def card(rate=87.0, scored=1082, **summary):
    base = {'scored': scored, 'agreed': 941, 'agreement_rate': rate, 'total_disagreements': 14,
            'disagreement_classes': 3, 'drift': {'delta': -6.0, 'direction': 'declining'},
            'few_shot': {'gold_exemplar_retrieval_enabled': True, 'note': 'Retrieval note.'}}
    base.update(summary)
    return {'summary': base}


@pytest.fixture
def scorecard_reads(monkeypatch):
    from ion.services import de_bob_service, de_proposal_service
    data = {'card': card(), 'drafted': [{'status': 'applied'}, {'status': 'draft'}],
            'by_rule': {'rules': [{'rule_name': 'MFA fatigue', 'agreement_rate': 68.2, 'scored': 22, 'disagreed': 7}],
                        'below_minimum': 4}}
    monkeypatch.setattr(de_bob_service, 'get_bob_scorecard', lambda *a, **k: _returns(data['card'])())
    monkeypatch.setattr(de_proposal_service, 'list_proposals', lambda *a, **k: _returns(data['drafted'])())
    monkeypatch.setattr(de_bob_service, 'get_agreement_by_rule', lambda *a, **k: _returns(data['by_rule'])())
    return data


def test_scorecard_tiles(make_client, scorecard_reads):
    soup = BeautifulSoup(make_client().get('/ui/detection-engineering/bob/scorecard').text, 'html.parser')
    tile = lambda f: soup.select_one(f'[data-field="{f}"]').get_text(' ', strip=True)
    assert tile('agreement_rate') == '87%'
    assert tile('scored') == '1,082'
    assert tile('disagreements') == '14'
    assert tile('accepted') == '1 / 2'
    assert tile('drift') == '-6.0 pts'
    assert 'MFA fatigue' in soup.select_one('table').get_text()
    # Tiles there is no data for are dropped rather than invented.
    assert 'Hours saved' not in soup.get_text() and 'Guide corrections' not in soup.get_text()


def test_scorecard_failed_read_is_not_a_zero(make_client, scorecard_reads):
    scorecard_reads['card'] = RuntimeError('ledger down')
    client = make_client()
    assert client.get('/ui/detection-engineering/bob/scorecard', headers=JSON).json()['state'] == 'failed'
    html = client.get('/ui/detection-engineering/bob/scorecard').text
    assert 'could not be read' in html and 'data-field="agreement_rate"' not in html


def test_scorecard_empty_and_measured_zero(make_client, scorecard_reads):
    scorecard_reads['card'] = card(rate=None, scored=0)
    client = make_client()
    assert client.get('/ui/detection-engineering/bob/scorecard', headers=JSON).json()['state'] == 'empty'
    assert 'No scored verdicts' in client.get('/ui/detection-engineering/bob/scorecard').text
    scorecard_reads['card'] = card(rate=0.0, scored=5)
    soup = BeautifulSoup(client.get('/ui/detection-engineering/bob/scorecard').text, 'html.parser')
    assert soup.select_one('[data-field="agreement_rate"]').get_text(strip=True) == '0%'


def test_agreement_by_rule_states_are_separate_from_the_tiles(make_client, scorecard_reads):
    client = make_client()
    scorecard_reads['by_rule'] = RuntimeError('boom')
    html = client.get('/ui/detection-engineering/bob/scorecard').text
    assert 'Agreement by rule could not be read' in html and 'data-field="agreement_rate"' in html
    scorecard_reads['by_rule'] = {'rules': [], 'below_minimum': 4}
    assert 'No rule has 20 scored verdicts' in client.get('/ui/detection-engineering/bob/scorecard').text
    scorecard_reads['drafted'] = RuntimeError('boom')
    soup = BeautifulSoup(client.get('/ui/detection-engineering/bob/scorecard').text, 'html.parser')
    assert soup.select_one('[data-field="accepted"]').get_text(strip=True) == '—'


def test_agreement_by_rule_is_worst_first_and_skips_thin_and_unscored_rules(monkeypatch):
    from ion.services import de_bob_service
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    def row(agreement, rule, bob='false_positive', auto=False):
        return (agreement, bob, 'true_positive', auto, now, 'a', 1, None, rule)
    rows = ([row(True, 'good')] * 19 + [row(False, 'good')]
            + [row(True, 'bad')] * 10 + [row(False, 'bad')] * 10
            + [row(True, 'thin')] * 5
            + [row(False, 'bad', auto=True)] * 50 + [row(None, 'bad')] * 50 + [row(False, 'bad', bob=None)] * 50)
    monkeypatch.setattr(de_bob_service, '_deduped_rows', lambda session, cutoff: rows)
    result = de_bob_service.get_agreement_by_rule(None, days=90, min_verdicts=20)
    assert [(r['rule_name'], r['agreement_rate'], r['scored'], r['disagreed']) for r in result['rules']] == [
        ('bad', 50.0, 20, 10), ('good', 95.0, 20, 1)]
    assert result['below_minimum'] == 1


FEEDBACK = {'total_disagreements': 14, 'classes': [
    {'rule_name': 'MFA fatigue', 'bob_verdict': 'false_positive', 'human_verdict': 'true_positive', 'count': 9,
     'sample_reasons': ['user confirmed not them']},
    {'rule_name': 'Kerberoasting', 'bob_verdict': 'false_positive', 'human_verdict': 'escalated', 'count': 5,
     'sample_reasons': 'not a list'}]}


@pytest.mark.parametrize('payload,state', [(RuntimeError('down'), 'failed'), ({'error': 'x'}, 'failed'),
                                           ({'classes': [], 'total_disagreements': 0}, 'empty'), (FEEDBACK, 'data')])
def test_disagreements_three_states(make_client, monkeypatch, payload, state):
    from ion.services import de_bob_service
    monkeypatch.setattr(de_bob_service, 'get_bob_feedback', _returns(payload))
    client = make_client()
    assert client.get('/ui/detection-engineering/bob/disagreements', headers=JSON).json()['state'] == state
    soup = BeautifulSoup(client.get('/ui/detection-engineering/bob/disagreements').text, 'html.parser')
    count = soup.select_one('#de-count-disagreements').get_text()
    assert count == {'failed': '', 'empty': '0', 'data': '14'}[state]
    assert ('Bob and the analysts agree' in soup.get_text()) is (state == 'empty')
    if state == 'data':
        assert len(soup.select('tbody tr')) == 2 and 'user confirmed not them' in soup.get_text()
        assert 'not a list' not in soup.get_text()


def test_draft_from_a_disagreement_needs_de_propose(make_client, monkeypatch):
    from ion.services import de_bob_service
    monkeypatch.setattr(de_bob_service, 'get_bob_feedback', _returns(FEEDBACK))
    reader = make_client({'de:read'}).get('/ui/detection-engineering/bob/disagreements').text
    assert 'bbDraft' not in reader and 'bb-draft-dialog' not in reader
    proposer = make_client({'de:read', 'de:propose'}).get('/ui/detection-engineering/bob/disagreements').text
    assert 'bbDraft' in proposer and 'bb-draft-dialog' in proposer


SCAN = {'window_days': 90, 'signals': [
    {'type': 'collusion_pair', 'severity': 'high', 'count': 9, 'description': 'users 3 and 4 co-signed 9'},
    {'type': 'broad_scope_quirk', 'severity': 'medium', 'rule_count': 14, 'description': 'quirk #2 <b>'}],
    'summary': {'total': 2, 'by_severity': {'high': 1, 'medium': 1, 'low': 0}}}


def test_abuse_monitor_needs_de_verify_on_the_server(make_client, monkeypatch):
    from ion.services import de_abuse_service
    calls = []
    monkeypatch.setattr(de_abuse_service, 'scan_abuse', lambda *a, **k: calls.append(k) or SCAN)
    assert make_client({'de:read', 'de:propose', 'de:approve'}).get('/ui/detection-engineering/bob/abuse').status_code == 403
    assert calls == []
    response = make_client({'de:read', 'de:verify'}).get('/ui/detection-engineering/bob/abuse')
    assert response.status_code == 200 and '14 rules' in response.text and '&lt;b&gt;' in response.text


@pytest.mark.parametrize('scan,state', [(RuntimeError('down'), 'failed'), ({'summary': {}}, 'failed'),
                                        ({'signals': [], 'summary': {}}, 'empty'), (SCAN, 'data')])
def test_abuse_three_states(make_client, monkeypatch, scan, state):
    from ion.services import de_abuse_service
    monkeypatch.setattr(de_abuse_service, 'scan_abuse', _returns(scan))
    client = make_client()
    assert client.get('/ui/detection-engineering/bob/abuse', headers=JSON).json()['state'] == state
    html = client.get('/ui/detection-engineering/bob/abuse').text
    assert ('No abuse signals' in html) is (state == 'empty')
    assert ('scan failed' in html) is (state == 'failed')


@pytest.mark.parametrize('path', ['scorecard', 'disagreements', 'abuse'])
def test_every_bob_route_needs_de_read(make_client, path):
    assert make_client({'de:verify'}).get('/ui/detection-engineering/bob/' + path).status_code == 403
