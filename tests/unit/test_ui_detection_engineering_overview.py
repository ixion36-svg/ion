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
    state = {'posture': POSTURE, 'disabled': DISABLED, 'gaps': _gaps(), 'use_cases': USE_CASES}

    def answer(key):
        def read(**kwargs):
            value = state[key]
            if isinstance(value, Exception):
                raise value
            return value
        return read

    monkeypatch.setattr(de_tide_api, 'tide_de_posture', answer('posture'))
    monkeypatch.setattr(de_tide_api, 'tide_de_disabled_critical', answer('disabled'))
    monkeypatch.setattr(de_tide_api, 'tide_de_gaps', answer('gaps'))
    monkeypatch.setattr(de_tide_api, 'tide_de_use_cases', answer('use_cases'))
    return state


def _field(html, name):
    cell = BeautifulSoup(html, 'html.parser').select_one(f'[data-field="{name}"]')
    assert cell is not None, name
    return cell.get_text(' ', strip=True)


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

def test_eight_tabs_and_every_old_tab_id_still_resolves():
    source = (ROOT / 'src/ion/web/templates/detection_engineering.html').read_text(encoding='utf-8')
    script = (ROOT / 'src/ion/web/static/js/detection-engineering.js').read_text(encoding='utf-8')
    soup = BeautifulSoup(source, 'html.parser')
    assert [tab['data-tab'] for tab in soup.select('.dx-tab')] == [
        'overview', 'coverage', 'systems', 'rules', 'usecases', 'readiness', 'work', 'bob']
    sub_tab = dict(re.findall(r"(\w+):'(\w+)'", re.search(r'const SUB_TAB = \{(.*?)\};', script, re.S).group(1)))
    aliases = dict(re.findall(r"'?([\w-]+)'?:'(\w+)'", re.search(r'const ALIASES = \{(.*?)\};', script, re.S).group(1)))
    resolve = lambda name: aliases.get(name, name)
    for old in ['posture', 'gaps', 'coverage', 'usecases', 'execution', 'killchains', 'progression', 'rules',
                'readiness', 'emulation', 'vulns', 'd3fend']:
        assert resolve(old) in sub_tab, old
        assert soup.select_one(f'#de-panel-{resolve(old)}') is not None, old
    for anchor in ['requests', 'proposals', 'quirks', 'scorecard', 'abuse', 'health', 'systems']:
        assert anchor in sub_tab, anchor


@pytest.mark.parametrize('name', ['detection_engineering.html', '_fragments/detection_engineering_overview.html',
                                  '_fragments/detection_engineering_coverage.html',
                                  '_fragments/detection_engineering_rules.html', '_fragments/detection_engineering_rule_drawer.html',
                                  '_fragments/detection_engineering_health.html', '_fragments/detection_engineering_systems.html',
                                  '_fragments/detection_engineering_system_detail.html'])
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
