"""Overview and coverage map: one screen built from the existing reads.

The guarantees are the ones the older panels make. A figure a read could
not supply is drawn as a dash with its reason, never as a zero, and the
JSON model says None for it.
"""
from pathlib import Path
import re
from types import SimpleNamespace

from bs4 import BeautifulSoup
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from ion.services import attack_catalogue
from ion.storage.database import get_db_session
from ion.web import de_tide_api
from ion.web.ui import _detection_engineering_overview as ui

ROOT = Path(__file__).resolve().parents[2]
JSON = {'Accept': 'application/json'}

POSTURE = {
    'enabled': True, 'total_rules': 4, 'enabled_rules': 3, 'disabled_rules': 1, 'unmapped_rules': 1,
    'covered_techniques': 3, 'total_techniques': 706, 'total_systems': 2,
    'severity': {'critical': {'total': 1, 'enabled': 1, 'disabled': 0}, 'high': {'total': 1, 'enabled': 0, 'disabled': 1},
                 'medium': {'total': 1, 'enabled': 1, 'disabled': 0}, 'low': {'total': 1, 'enabled': 1, 'disabled': 0}},
    'quality': {'scale': 'percent', 'excellent': 1, 'good': 1, 'fair': 1, 'poor': 1, 'avg_quality': 46.3},
}
DISABLED = [{'rule_id': 'rule-b', 'name': 'SMB lateral movement', 'severity': 'high', 'quality_score': 60, 'mitre_ids': ['T1021']}]


def _gaps(covered=('T1003', 'T1059', 'T1486')):
    by_tactic = {}
    for technique in attack_catalogue.techniques():
        if technique['technique_id'] not in covered:
            by_tactic.setdefault(technique['tactic'] or 'unknown', []).append({'id': technique['technique_id'], 'name': technique['name']})
    return {'enabled': True, 'blind_spots_by_tactic': by_tactic, 'total_blind_spots': sum(map(len, by_tactic.values())),
            'unmapped_rules': [{'rule_id': 'rule-d', 'name': 'Unmapped <noise>', 'severity': 'low', 'enabled': 1, 'quality_score': 10}],
            'quick_wins': DISABLED, 'systems_coverage': [{'id': 'sys-a', 'name': 'Corporate AD', 'applied_rules': 2}]}


USE_CASES = [
    {'name': 'Ransomware', 'technique_coverage_measured': True, 'technique_coverage': {'T1486': {'rule_count': 1, 'enabled_rules': 1}, 'T1021': {'rule_count': 1, 'enabled_rules': 0}},
     'steps': [{'order': 1, 'techniques': ['T1486']}, {'order': 2, 'techniques': ['T1021']}]},
    {'name': 'Insider', 'technique_coverage_measured': True, 'technique_coverage': {},
     'steps': [{'order': 1, 'techniques': ['T1200']}, {'order': 2, 'techniques': ['T1052']}]},
    {'name': 'Ready one', 'technique_coverage_measured': True, 'technique_coverage': {'T1003': {'rule_count': 1, 'enabled_rules': 1}},
     'steps': [{'order': 1, 'techniques': ['T1003']}]},
]

EXECUTION = {
    'enabled': True, 'hours': 168,
    'summary': {'total_alerts': 10000, 'unique_rules_firing': 5, 'noisy_rules': 1, 'silent_enabled_rules': 3,
                'status': {'open': 25126, 'acknowledged': 4844, 'closed': 30}},
    'timeline': [{'timestamp': 'a', 'count': 0}, {'timestamp': 'b', 'count': 9}, {'timestamp': 'c', 'count': 3}],
    'severity_timeline': [],
    'top_firing': [{'rule_name': 'LT Brute Force', 'alert_count': 6000, 'open': 5000, 'close_rate': 0.1, 'mitre_ids': ['T1110'], 'in_tide': False},
                   {'rule_name': 'Credential dumping', 'alert_count': 12, 'open': 1, 'close_rate': 80, 'mitre_ids': [], 'in_tide': True,
                    'tide_severity': 'critical', 'tide_quality': 85}],
    'noisy_rules': [{'rule_name': 'Credential dumping', 'alert_count': 12}],
    'silent_rules': [{'rule_name': 'Mass file encryption', 'tide_severity': 'medium', 'tide_quality': 30, 'mitre_ids': ['T1486']}],
}


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(ui.router, prefix='/ui')
    for route in ui.router.routes:
        for dependency in route.dependant.dependencies:
            if dependency.call is not get_db_session:
                app.dependency_overrides[dependency.call] = lambda: SimpleNamespace(has_permission=lambda permission: True)
    app.dependency_overrides[get_db_session] = lambda: None
    return TestClient(app)


@pytest.fixture
def reads(monkeypatch):
    """Every read the overview makes, answering with the loadtest's shape."""
    state = {'posture': POSTURE, 'disabled': DISABLED, 'gaps': _gaps(), 'use_cases': USE_CASES, 'execution': EXECUTION}

    def answer(key):
        def read(**kwargs):
            value = state[key]
            if isinstance(value, Exception):
                raise value
            return value
        return read

    async def execution(**kwargs):
        value = state['execution']
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(de_tide_api, 'tide_de_posture', answer('posture'))
    monkeypatch.setattr(de_tide_api, 'tide_de_disabled_critical', answer('disabled'))
    monkeypatch.setattr(de_tide_api, 'tide_de_gaps', answer('gaps'))
    monkeypatch.setattr(de_tide_api, 'tide_de_use_cases', answer('use_cases'))
    monkeypatch.setattr(de_tide_api, 'tide_de_execution', execution)
    return state


def _field(html, name):
    cell = BeautifulSoup(html, 'html.parser').select_one(f'[data-field="{name}"]')
    assert cell is not None, name
    return cell.get_text(' ', strip=True)


def test_overview_combines_posture_gaps_use_cases_and_execution(client, reads):
    model = client.get('/ui/detection-engineering/overview', headers=JSON).json()
    assert model['state'] == 'data'
    assert model['coverage_pct'] == 0.4
    assert model['use_case_counts'] == {'total': 3, 'ready': 1, 'partial': 1, 'blind': 1, 'unknown': 0, 'empty': 0}
    assert model['firing']['capped'] is True
    assert model['needs_action']['total'] == 1 + 1 + 3
    assert model['needs_action']['partial'] is False
    credential = next(row for row in model['tactics'] if row['name'] == 'Credential Access')
    assert credential['covered'] == 1 and credential['total'] == 58 and credential['gaps'] == 57

    html = client.get('/ui/detection-engineering/overview').text
    assert _field(html, 'total_rules') == '4'
    assert _field(html, 'coverage_pct').startswith('0.4%')
    assert _field(html, 'avg_quality').startswith('46%')
    assert _field(html, 'use_cases_ready') == '1 / 3'
    # Elasticsearch stopped counting at 10,000; the page says so rather than claim it.
    assert _field(html, 'firing_total') == '≥10,000'
    assert 'Excellent (80%+)' in html
    assert 'Unmapped &lt;noise&gt;' in html and BeautifulSoup(html, 'html.parser').find('noise') is None
    soup = BeautifulSoup(html, 'html.parser')
    assert soup.select_one('#de-count-coverage').get_text(strip=True) == '703 gaps'
    assert soup.select_one('#de-count-coverage')['hx-swap-oob'] == 'true'


@pytest.mark.parametrize('scale,label,avg', [('points', 'Excellent (30+)', '46.3 points'), ('percent', 'Excellent (80%+)', '46% TIDE score')])
def test_overview_quality_follows_the_tide_scale(client, reads, scale, label, avg):
    reads['posture'] = {**POSTURE, 'quality': {**POSTURE['quality'], 'scale': scale}}
    html = client.get('/ui/detection-engineering/overview').text
    assert label in html
    assert _field(html, 'avg_quality') == avg


def test_overview_failed_posture_is_unknown_not_zero(client, reads):
    reads['posture'] = None
    model = client.get('/ui/detection-engineering/overview', headers=JSON).json()
    assert model['state'] == 'failed'
    assert model['coverage_pct'] is None
    html = client.get('/ui/detection-engineering/overview').text
    assert 'Failed to load posture' in html
    for field in ('total_rules', 'coverage_pct', 'avg_quality'):
        assert _field(html, field) == '—'
    # The gap analysis is a separate read and still draws.
    assert 'Credential Access' in html


def test_overview_failed_execution_shows_reason_and_partial_needs_action(client, reads):
    reads['execution'] = {'enabled': False, 'error': 'Elasticsearch not configured'}
    model = client.get('/ui/detection-engineering/overview', headers=JSON).json()
    assert model['firing']['total'] is None
    assert model['needs_action']['partial'] is True
    assert model['needs_action']['total'] == 2
    html = client.get('/ui/detection-engineering/overview').text
    assert _field(html, 'firing_total') == '—'
    assert 'Elasticsearch not configured' in html
    assert _field(html, 'needs_action') == '≥2'
    assert 'silent unknown' in html


def test_overview_nothing_readable_is_a_dash(client, reads):
    reads.update(posture=None, disabled=RuntimeError('private detail'), gaps=None, use_cases=None, execution=RuntimeError('x'))
    model = client.get('/ui/detection-engineering/overview', headers=JSON).json()
    assert model['needs_action']['total'] is None
    assert model['tactics'] is None and model['use_cases'] is None
    html = client.get('/ui/detection-engineering/overview').text
    assert _field(html, 'needs_action') == '—'
    assert _field(html, 'use_cases_ready') == '—'
    assert 'Coverage by tactic unavailable' in html
    assert 'private detail' not in html


def test_overview_unconfigured(client, reads):
    reads['posture'] = {'enabled': False}
    html = client.get('/ui/detection-engineering/overview').text
    assert 'TIDE not configured' in html
    assert 'data-field="total_rules"' not in html


def test_unmeasured_use_case_step_is_not_blind(client, reads):
    reads['use_cases'] = [{'name': 'Half read', 'technique_coverage_measured': False, 'technique_coverage': {},
                           'steps': [{'order': 1, 'techniques': ['T1200']}]}]
    model = client.get('/ui/detection-engineering/overview', headers=JSON).json()
    assert model['use_case_counts']['unknown'] == 1 and model['use_case_counts']['blind'] == 0
    assert model['use_cases'][0]['pct'] is None


def test_needs_action_lists_disabled_unmapped_and_silent(client, reads):
    html = client.get('/ui/detection-engineering/overview').text
    feed = BeautifulSoup(html, 'html.parser').select('.dx-feed .dx-row')
    text = [row.get_text(' ', strip=True) for row in feed]
    assert any('SMB lateral movement is disabled' in item and 'quick win' in item for item in text)
    assert any('has no ATT&CK mapping' in item for item in text)
    assert any('Mass file encryption has not fired in 7 days' in item for item in text)


# ── Coverage map ─────────────────────────────────────────────────────

def _global(states):
    techniques = {}
    for technique in attack_catalogue.techniques():
        enabled, total = states.get(technique['technique_id'], (0, 0))
        techniques[technique['technique_id']] = {'name': technique['name'], 'tactic': technique['tactic'],
                                                 'rule_count': total, 'enabled_rules': enabled, 'systems': []}
    return {'enabled': True, 'techniques': techniques}


@pytest.fixture
def coverage_reads(reads, monkeypatch):
    reads['global'] = _global({'T1003': (1, 1), 'T1021': (0, 1)})
    monkeypatch.setattr(de_tide_api, 'tide_global_mitre_coverage', lambda: reads['global'])
    return reads


def _states(model):
    return {cell['id']: cell['state'] for tactic in model['tactics'] for cell in tactic['cells']}


def test_coverage_map_four_states_from_global_coverage(client, coverage_reads):
    model = client.get('/ui/detection-engineering/coverage', headers=JSON).json()
    assert model['basis'] == 'global'
    states = _states(model)
    assert states['T1003'] == 'on'
    assert states['T1021'] == 'off'
    assert states['T1200'] == 'usecase'
    assert states['T1110'] == 'none'
    assert model['totals']['total'] == len(attack_catalogue.techniques())
    assert [tactic['name'] for tactic in model['tactics']][:3] == ['Reconnaissance', 'Resource Development', 'Initial Access']
    assert 'Stealth' in [tactic['name'] for tactic in model['tactics']]
    assert model['selected'] in {'Credential Access', 'Execution', 'Impact'}

    soup = BeautifulSoup(client.get('/ui/detection-engineering/coverage').text, 'html.parser')
    columns = soup.select('.dx-mcol')
    assert len(columns) == len(model['tactics'])
    assert all(column['data-click-action'] == 'deCoverageTactic' for column in columns)
    panels = soup.select('[data-tactic-panel]')
    assert [panel for panel in panels if not panel.has_attr('hidden')][0]['data-tactic-panel'] == model['selected']


def test_coverage_falls_back_to_gaps_and_says_rule_off_is_unknown(client, coverage_reads):
    coverage_reads['global'] = {'enabled': True, 'error': 'boom'}
    model = client.get('/ui/detection-engineering/coverage', headers=JSON).json()
    assert model['basis'] == 'gaps'
    states = _states(model)
    assert states['T1003'] == 'on' and states['T1021'] == 'usecase' and states['T1110'] == 'none'
    assert 'off' not in set(states.values())
    assert any('Rule-off state unavailable' in notice for notice in model['notices'])


def test_coverage_without_either_read_fails_rather_than_draw_blind(client, coverage_reads):
    coverage_reads.update(gaps=None, **{'global': None})
    model = client.get('/ui/detection-engineering/coverage', headers=JSON).json()
    assert model['state'] == 'failed' and model['tactics'] is None


def test_coverage_unknown_rule_counts_are_not_no_rule(client, coverage_reads):
    coverage_reads['global']['techniques']['T1110'] = {'name': 'Brute Force', 'rule_count': None, 'enabled_rules': None}
    assert _states(client.get('/ui/detection-engineering/coverage', headers=JSON).json())['T1110'] == 'unknown'


def test_coverage_scoped_to_one_system(client, coverage_reads, monkeypatch):
    monkeypatch.setattr(de_tide_api, 'tide_de_systems', lambda **kwargs: [{'id': 'sys-a', 'name': 'Corporate AD'}])
    monkeypatch.setattr(de_tide_api, 'tide_system_mitre', lambda system_id: {'covered': ['T1059.001']})
    model = client.get('/ui/detection-engineering/coverage?system_id=sys-a', headers=JSON).json()
    assert model['basis'] == 'system' and model['system']['name'] == 'Corporate AD'
    states = _states(model)
    assert states['T1059'] == 'on' and states['T1059.001'] == 'on' and states['T1003'] == 'usecase' and states['T1110'] == 'none'

    monkeypatch.setattr(de_tide_api, 'tide_system_mitre', lambda system_id: None)
    model = client.get('/ui/detection-engineering/coverage?system_id=sys-a', headers=JSON).json()
    assert model['state'] == 'failed'


def test_coverage_unconfigured(client, coverage_reads):
    coverage_reads['gaps'] = {'enabled': False}
    assert client.get('/ui/detection-engineering/coverage', headers=JSON).json()['state'] == 'unconfigured'


@pytest.mark.parametrize('payload,state,options', [(None, 'failed', 1), ([], 'empty', 1), ([{'id': 'a"<b>', 'name': '<x>'}], 'data', 2)])
def test_system_options(client, monkeypatch, payload, state, options):
    monkeypatch.setattr(de_tide_api, 'tide_de_systems', lambda **kwargs: payload)
    assert client.get('/ui/detection-engineering/system-options', headers=JSON).json()['state'] == state
    soup = BeautifulSoup(client.get('/ui/detection-engineering/system-options').text, 'html.parser')
    assert len(soup.select('option')) == options
    assert soup.find('b') is None and soup.find('x') is None


# ── Shell ────────────────────────────────────────────────────────────

def test_five_tabs_and_every_old_tab_id_still_resolves():
    source = (ROOT / 'src/ion/web/templates/detection_engineering.html').read_text(encoding='utf-8')
    soup = BeautifulSoup(source, 'html.parser')
    assert [tab['data-tab'] for tab in soup.select('.dx-tab')] == ['overview', 'coverage', 'usecases', 'rules', 'readiness']
    sub_tab = re.search(r'const SUB_TAB = \{(.*?)\};', source, re.S).group(1)
    aliases = re.search(r'const ALIASES = \{(.*?)\};', source, re.S).group(1)
    known = set(re.findall(r'(\w+):', sub_tab)) | set(re.findall(r'(\w+):', aliases))
    for old in ['posture', 'killchains', 'rules', 'execution', 'readiness', 'progression', 'gaps', 'd3fend', 'emulation', 'vulns']:
        assert old in known, old
    for panel in ['killchains', 'rules', 'execution', 'readiness', 'progression', 'd3fend', 'emulation', 'vulns']:
        assert soup.select_one(f'#de-panel-{panel}') is not None, panel


@pytest.mark.parametrize('name', ['detection_engineering.html', '_fragments/detection_engineering_overview.html',
                                  '_fragments/detection_engineering_coverage.html'])
def test_csp_no_inline_styles_or_handlers(name):
    source = (ROOT / 'src/ion/web/templates' / name).read_text(encoding='utf-8')
    markup = re.sub(r'<script\b.*?</script>', '', source, flags=re.S)
    assert not re.search(r'\sstyle\s*=', markup)
    assert not re.search(r'\son[a-z]+\s*=', markup)
    assert '<style' not in markup


def test_page_links_its_own_stylesheet():
    source = (ROOT / 'src/ion/web/templates/detection_engineering.html').read_text(encoding='utf-8')
    assert '/static/css/detection-engineering.css' in source
    assert (ROOT / 'src/ion/web/static/css/detection-engineering.css').is_file()


@pytest.mark.parametrize('value,total,expected', [(3, 706, 0.4), (0, 3, 0), (1, 2, 50), (3, 3, 100), (None, 3, None), (3, 0, None), (3, None, None)])
def test_percent_keeps_a_small_share_visible_and_unknown_unknown(value, total, expected):
    assert ui.percent(value, total) == expected
