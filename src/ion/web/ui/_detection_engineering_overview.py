"""Overview and ATT&CK coverage map, built from the reads the other panels make.

Nothing here asks TIDE anything new. The overview folds together the
posture, gap, use-case and execution reads the older tabs already made; the
coverage map adds TIDE's global coverage read (the one the navigator layer
uses) for the rule-off state, and the per-system read when a system is
chosen. A figure that one of those reads could not supply is None, which
the templates draw as a dash with the reason, never as a zero.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Literal, TypedDict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ion.auth.dependencies import require_permission
from ion.services import attack_catalogue
from ion.storage.database import get_db_session
from ion.web import de_tide_api
from ion.web.ui._detection_engineering_core import GapsPanel, PosturePanel, _number, gaps_view, posture_view
from ion.web.ui._detection_engineering_execution import ExecutionView, execution_view
from ion.web.ui._detection_engineering_rules import use_cases
from ion.web.ui._shared import render_view

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_permission('alert:read'))])

OVERVIEW_HOURS = 168
SEVERITIES = ('critical', 'high', 'medium', 'low')
OTHER_TACTIC = 'Other'
TACTIC_IDS = {name: tactic_id for tactic_id, name in attack_catalogue.TACTIC_NAMES.items()}
# Column headings on the coverage map, where fifteen columns share the width.
SHORT_TACTICS = {'Reconnaissance': 'Recon', 'Resource Development': 'Resource Dev.', 'Privilege Escalation': 'Priv. Escalation',
                 'Defense Impairment': 'Defense Impair.', 'Command and Control': 'C2', 'Credential Access': 'Credential Access'}
NEEDS_ACTION_SHOWN = 6
TACTICS_SHOWN = 6


class OverviewPanel(TypedDict):
    state: Literal['failed', 'unconfigured', 'empty', 'data']
    posture: PosturePanel
    coverage_pct: float | int | None
    tactics: list[dict[str, Any]] | None
    tactics_hidden: int
    use_cases: list[dict[str, Any]] | None
    use_case_counts: dict[str, int] | None
    firing: dict[str, Any]
    needs_action: dict[str, Any]
    blind_spots: int | float | None


class CoveragePanel(TypedDict):
    state: Literal['failed', 'unconfigured', 'data']
    error: str | None
    basis: Literal['global', 'gaps', 'system'] | None
    system: dict[str, Any] | None
    notices: list[str]
    tactics: list[dict[str, Any]] | None
    selected: str | None
    totals: dict[str, int] | None
    quick_wins: list[dict[str, Any]] | None
    unmapped_rules: list[dict[str, Any]] | None
    systems_coverage: list[dict[str, Any]] | None


class SystemOptions(TypedDict):
    state: Literal['failed', 'empty', 'data']
    systems: list[dict[str, Any]] | None


def percent(value: object, total: object) -> float | int | None:
    """A share of a total, with one decimal below 10% so 3 of 706 is not 0%."""
    value, total = _number(value), _number(total)
    if value is None or not total:
        return None
    share = value / total * 100
    if share == 0 or share >= 10:
        return round(share)
    return round(share, 1)


def catalogue_by_tactic() -> list[tuple[str, list[dict[str, Any]]]]:
    """ION's ATT&CK techniques grouped by tactic, in kill-chain order."""
    groups: dict[str, list[dict[str, Any]]] = {name: [] for name in attack_catalogue.TACTIC_NAMES.values()}
    for technique in attack_catalogue.techniques():
        groups.setdefault(technique['tactic'] or OTHER_TACTIC, []).append(technique)
    return [(name, techniques) for name, techniques in groups.items() if techniques]


def _blind_ids(gaps: GapsPanel) -> set[str] | None:
    """Techniques with no enabled rule, by id, from the gap analysis."""
    tactics = gaps['blind_spots_by_tactic']
    if tactics is None:
        return None
    found: set[str] = set()
    for techniques in tactics.values():
        for technique in techniques:
            if not isinstance(technique.get('id'), str):
                return None
            found.add(technique['id'])
    return found


def _tactic_rows(blind: set[str] | None) -> list[dict[str, Any]] | None:
    if blind is None:
        return None
    result = []
    for order, (name, techniques) in enumerate(catalogue_by_tactic()):
        gaps = sum(technique['technique_id'] in blind for technique in techniques)
        covered = len(techniques) - gaps
        result.append({'name': name, 'total': len(techniques), 'gaps': gaps, 'covered': covered,
                       'pct': percent(covered, len(techniques)), 'order': order})
    return sorted(result, key=lambda row: (-row['covered'], -(row['pct'] or 0), row['order']))


def _use_case_summary(playbooks: list[dict[str, Any]] | None) -> tuple[list[dict[str, Any]] | None, dict[str, int] | None]:
    if playbooks is None:
        return None, None
    counts = {'total': len(playbooks), 'ready': 0, 'partial': 0, 'blind': 0, 'unknown': 0, 'empty': 0}
    summary = []
    for playbook in playbooks:
        steps = playbook.get('steps')
        states = [step.get('coverage_state', 'unknown') for step in steps if isinstance(step, dict)] if isinstance(steps, list) else None
        if states is None or 'unknown' in states:
            state = 'unknown'
        elif not states:
            state = 'empty'
        elif all(item == 'covered' for item in states):
            state = 'ready'
        elif all(item == 'blind' for item in states):
            state = 'blind'
        else:
            state = 'partial'
        counts[state] += 1
        covered = states.count('covered') if state != 'unknown' else None
        summary.append({'name': playbook.get('name'), 'state': state, 'steps': states or [],
                        'covered': covered, 'total': len(states) if states is not None else None,
                        'pct': percent(covered, len(states)) if covered is not None and states else None})
    return summary, counts


def _sparkline(timeline: list[dict[str, Any]] | None, width: int = 90, height: int = 28) -> str | None:
    """SVG polyline points for a volume series, or None when any bucket is unknown."""
    if not timeline or len(timeline) < 2 or any(item.get('count') is None for item in timeline):
        return None
    peak = max(item['count'] for item in timeline) or 1
    step = width / (len(timeline) - 1)
    return ' '.join(f"{index * step:.1f},{height - 2 - item['count'] / peak * (height - 4):.1f}"
                    for index, item in enumerate(timeline))


def _firing(execution: ExecutionView) -> dict[str, Any]:
    summary = execution['summary']
    if execution['state'] == 'failed' or summary is None:
        return {'total': None, 'reason': execution['error'] or 'Execution metrics unavailable', 'capped': False,
                'rules': None, 'noisy': None, 'silent': None, 'spark': None, 'top': None, 'noisy_names': set(),
                'hours': execution['hours']}
    total = _number(summary.get('total_alerts'))
    status = summary.get('status')
    counted = [_number(value) for value in status.values()] if isinstance(status, dict) and status else None
    status_sum = sum(counted) if counted and all(value is not None for value in counted) else None
    noisy = execution['noisy_rules']
    top = execution['top_firing']
    return {
        'total': total, 'reason': None,
        # Elasticsearch reports at most 10,000 hits unless asked to count them
        # all. The status buckets are exact, so more alerts by status than
        # hits means the hit total is a floor, not a count.
        'capped': total is not None and status_sum is not None and status_sum > total,
        'rules': _number(summary.get('unique_rules_firing')),
        'noisy': _number(summary.get('noisy_rules')),
        'silent': _number(summary.get('silent_enabled_rules')),
        'spark': _sparkline(execution['timeline']),
        'top': [rule for rule in top if isinstance(rule, dict)][:10] if isinstance(top, list) else None,
        'noisy_names': {rule.get('rule_name') for rule in noisy if isinstance(rule, dict)} if isinstance(noisy, list) else set(),
        'hours': execution['hours'],
    }


def _needs_action(posture: PosturePanel, gaps: GapsPanel, execution: ExecutionView, firing: dict[str, Any]) -> dict[str, Any]:
    disabled = posture['disabled_critical']
    unmapped = gaps['unmapped_rules']
    silent = execution['silent_rules'] if firing['reason'] is None and isinstance(execution['silent_rules'], list) else None
    unmapped_count = posture['stats']['unmapped_rules']
    if unmapped_count is None and unmapped is not None and len(unmapped) < 100:
        unmapped_count = len(unmapped)
    parts = [
        {'key': 'disabled', 'label': 'disabled critical/high', 'count': len(disabled) if disabled is not None else None,
         'reason': 'disabled-rule list unavailable'},
        {'key': 'unmapped', 'label': 'unmapped', 'count': unmapped_count, 'reason': 'unmapped count unavailable'},
        {'key': 'silent', 'label': 'silent', 'count': firing['silent'] if silent is not None else None,
         'reason': 'silent rules need execution data' + (f" ({firing['reason']})" if firing['reason'] else '')},
    ]
    quick = {rule.get('rule_id') or rule.get('name') for rule in gaps['quick_wins'] or []}
    items = []
    for rule in disabled or []:
        items.append({'kind': 'disabled', 'name': rule.get('name'), 'severity': rule.get('severity'),
                      'quality': _number(rule.get('quality_score')), 'mitre_ids': rule.get('mitre_ids') or [],
                      'quick_win': (rule.get('rule_id') or rule.get('name')) in quick})
    for rule in unmapped or []:
        items.append({'kind': 'unmapped', 'name': rule.get('name'), 'severity': rule.get('severity'),
                      'quality': _number(rule.get('quality_score')), 'enabled': rule.get('enabled'), 'mitre_ids': []})
    for rule in silent or []:
        if isinstance(rule, dict):
            items.append({'kind': 'silent', 'name': rule.get('rule_name'), 'severity': rule.get('tide_severity'),
                          'quality': _number(rule.get('tide_quality')), 'mitre_ids': rule.get('mitre_ids') or []})
    known = [part['count'] for part in parts if part['count'] is not None]
    return {'parts': parts, 'items': items[:NEEDS_ACTION_SHOWN], 'more': max(len(items) - NEEDS_ACTION_SHOWN, 0),
            'total': sum(known) if known else None, 'partial': len(known) < len(parts)}


def _snapshot_reads(session: Session | None) -> tuple[PosturePanel, GapsPanel, list[dict[str, Any]] | None]:
    return posture_view(session), gaps_view(session), use_cases(session)


@router.get('/detection-engineering/overview', response_class=HTMLResponse)
async def overview(request: Request, session: Session = Depends(get_db_session)):
    (posture, gaps, playbooks), execution = await asyncio.gather(
        run_in_threadpool(_snapshot_reads, session), execution_view(OVERVIEW_HOURS))
    firing = _firing(execution)
    tactics = _tactic_rows(_blind_ids(gaps))
    shown = [row for index, row in enumerate(tactics or []) if row['covered'] or index < TACTICS_SHOWN]
    summary, counts = _use_case_summary(playbooks)
    view: OverviewPanel = {
        'state': posture['state'], 'posture': posture,
        'coverage_pct': percent(posture['stats']['covered_techniques'], posture['stats']['total_techniques']),
        'tactics': shown if tactics is not None else None,
        'tactics_hidden': len(tactics or []) - len(shown),
        'use_cases': summary, 'use_case_counts': counts,
        'firing': {key: value for key, value in firing.items() if key != 'noisy_names'}
                  | {'noisy_names': sorted(name for name in firing['noisy_names'] if isinstance(name, str))},
        'needs_action': _needs_action(posture, gaps, execution, firing),
        'blind_spots': gaps['total_blind_spots'],
    }
    return render_view(request, '_fragments/detection_engineering_overview.html', view)


def _use_case_membership(playbooks: list[dict[str, Any]] | None) -> dict[str, list[str]] | None:
    if playbooks is None:
        return None
    members: dict[str, list[str]] = {}
    for playbook in playbooks:
        name = playbook.get('name') if isinstance(playbook.get('name'), str) else 'Unnamed use case'
        for step in playbook.get('steps') or []:
            for technique in step.get('techniques') or [] if isinstance(step, dict) else []:
                if isinstance(technique, str) and name not in members.setdefault(technique, []):
                    members[technique].append(name)
    return members


def _system(session: Session | None, system_id: str) -> tuple[dict[str, Any] | None, set[str] | None]:
    """The chosen system and the techniques its enabled, applied rules cover."""
    name = None
    try:
        systems = de_tide_api.tide_de_systems(session=session)
        if isinstance(systems, list):
            name = next((item.get('name') for item in systems if isinstance(item, dict) and str(item.get('id')) == system_id), None)
    except Exception:
        logger.exception('Could not read TIDE systems')
    try:
        payload = de_tide_api.tide_system_mitre(system_id)
        covered = payload.get('covered') if isinstance(payload, dict) else None
        if isinstance(covered, list) and all(isinstance(item, str) for item in covered):
            return {'id': system_id, 'name': name}, set(covered) | {item.split('.')[0] for item in covered}
    except Exception:
        logger.exception('Could not read system coverage')
    return {'id': system_id, 'name': name}, None


def coverage_view(session: Session | None, system_id: str = '') -> CoveragePanel:
    gaps = gaps_view(session)
    playbooks = use_cases(session)
    members = _use_case_membership(playbooks)
    notices: list[str] = []
    if members is None:
        notices.append('Use-case membership unavailable: the TIDE use-case read failed.')
    view: CoveragePanel = {
        'state': 'data', 'error': None, 'basis': None, 'system': None, 'notices': notices, 'tactics': None,
        'selected': None, 'totals': None, 'quick_wins': gaps['quick_wins'], 'unmapped_rules': gaps['unmapped_rules'],
        'systems_coverage': gaps['systems_coverage'],
    }
    if gaps['state'] == 'unconfigured':
        view['state'] = 'unconfigured'
        return view

    rules: dict[str, dict[str, Any]] | None = None
    covered: set[str] | None = None
    if system_id:
        view['system'], covered = _system(session, system_id)
        view['basis'] = 'system'
        if covered is None:
            view['state'], view['error'] = 'failed', 'Coverage for this system is unavailable: the TIDE system read failed.'
            return view
    else:
        payload = None
        try:
            payload = de_tide_api.tide_global_mitre_coverage()
        except Exception:
            logger.exception('Could not read global ATT&CK coverage')
        techniques = payload.get('techniques') if isinstance(payload, dict) and payload.get('enabled') is True else None
        if isinstance(techniques, dict) and all(isinstance(item, dict) for item in techniques.values()):
            rules, view['basis'] = techniques, 'global'
        else:
            blind = _blind_ids(gaps)
            if blind is None:
                view['state'], view['error'] = 'failed', 'ATT&CK coverage is unavailable: TIDE returned neither coverage nor gap analysis.'
                return view
            covered, view['basis'] = {item['technique_id'] for item in attack_catalogue.techniques()} - blind, 'gaps'
            notices.append('Rule-off state unavailable: TIDE coverage read failed, so a technique with only disabled rules shows as no enabled rule.')

    totals = {'on': 0, 'off': 0, 'usecase': 0, 'none': 0, 'unknown': 0, 'total': 0}
    tactics = []
    for name, techniques in catalogue_by_tactic():
        cells = []
        for technique in techniques:
            tid = technique['technique_id']
            in_use = members.get(tid, []) if members is not None else None
            counts = None
            if rules is not None:
                info = rules.get(tid) or {}
                enabled, total = _number(info.get('enabled_rules')), _number(info.get('rule_count'))
                counts = {'enabled': enabled, 'total': total}
                if enabled is None or total is None:
                    state = 'unknown'
                else:
                    state = 'on' if enabled else 'off' if total else 'usecase' if in_use else 'none'
            else:
                state = 'on' if tid in covered else 'usecase' if in_use else 'none'
            totals[state] += 1
            totals['total'] += 1
            cells.append({'id': tid, 'name': technique['name'], 'state': state, 'rules': counts, 'use_cases': in_use,
                          'systems': [item.get('name') for item in (rules.get(tid) or {}).get('systems') or [] if isinstance(item, dict)] if rules is not None else None})
        order = {'on': 0, 'off': 1, 'usecase': 2, 'none': 3, 'unknown': 4}
        tactics.append({
            'name': name, 'short': SHORT_TACTICS.get(name, name), 'id': TACTIC_IDS.get(name), 'cells': cells,
            'rows': sorted(cells, key=lambda cell: (order[cell['state']], cell['id'])),
            'covered': sum(cell['state'] == 'on' for cell in cells), 'off': sum(cell['state'] == 'off' for cell in cells),
            'total': len(cells),
        })
    view['tactics'] = tactics
    view['totals'] = totals
    ranked = sorted(tactics, key=lambda tactic: (-tactic['covered'], -tactic['off'], tactics.index(tactic)))
    view['selected'] = ranked[0]['name'] if ranked else None
    return view


@router.get('/detection-engineering/coverage', response_class=HTMLResponse)
def coverage(request: Request, system_id: str = '', session: Session = Depends(get_db_session)):
    return render_view(request, '_fragments/detection_engineering_coverage.html', coverage_view(session, system_id.strip()))


@router.get('/detection-engineering/system-options', response_class=HTMLResponse)
def system_options(request: Request, session: Session = Depends(get_db_session)):
    systems = None
    try:
        payload = de_tide_api.tide_de_systems(session=session)
        if isinstance(payload, list) and all(isinstance(item, dict) and item.get('id') is not None for item in payload):
            systems = payload
    except Exception:
        logger.exception('Could not read TIDE systems')
    view: SystemOptions = {'state': 'failed' if systems is None else 'data' if systems else 'empty', 'systems': systems}
    return render_view(request, '_fragments/detection_engineering_system_options.html', view)
