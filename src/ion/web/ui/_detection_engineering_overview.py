"""Overview (needs attention first) and the ATT&CK coverage map.

The overview reads what the other tabs read: posture and gaps from the TIDE
snapshot, rule health (TIDE Rule Monitoring, alert counts, ION closures) and
the systems report (CVEs with KEV, CIS, Wazuh agents). The coverage map adds
TIDE's global coverage read for the rule-off state, and the per-system read
when a system is chosen. A figure a read could not supply is None, which the
templates draw as a dash with the reason, never as a zero.
"""
from __future__ import annotations

import logging
from textwrap import shorten
from typing import Any, Literal, TypedDict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.services import attack_catalogue
from ion.services import de_systems_service as ds
from ion.services import rule_health_service as rh
from ion.services.tide_service import get_tide_service
from ion.storage.database import get_db_session
from ion.web import de_tide_api
from ion.web.ui._detection_engineering_core import GapsPanel, PosturePanel, _number, gaps_view, posture_view
from ion.web.ui._detection_engineering_rules import use_cases
from ion.web.ui._detection_engineering_health import spark_points
from ion.web.ui._detection_engineering_systems import baseline_summaries
from ion.web.ui._shared import render_view

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_permission('alert:read'))])

SEVERITIES = ('critical', 'high', 'medium', 'low')
OTHER_TACTIC = 'Other'
TACTIC_IDS = {name: tactic_id for tactic_id, name in attack_catalogue.TACTIC_NAMES.items()}
# Column headings on the coverage map, where fifteen columns share the width.
SHORT_TACTICS = {'Reconnaissance': 'Recon', 'Resource Development': 'Resource Dev.', 'Privilege Escalation': 'Priv. Escalation',
                 'Defense Impairment': 'Defense Impair.', 'Command and Control': 'C2', 'Credential Access': 'Credential Access'}
ATTENTION_SHOWN = 5
TACTICS_SHOWN = 6


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
    platform_scope: dict[str, Any] | None


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


def _row(lead: dict[str, Any], title: str, sub: str, action: dict[str, Any] | None, kind: str | None = None) -> dict[str, Any]:
    return {'lead': lead, 'title': title, 'kind': kind, 'sub': sub, 'action': action}


def _group(level: str, title: str, source: str, rows: list[dict[str, Any]], link: tuple[str, str] | None = None) -> dict[str, Any] | None:
    if not rows:
        return None
    return {'level': level, 'title': title, 'source': source, 'count': len(rows),
            'rows': rows[:ATTENTION_SHOWN], 'more': max(len(rows) - ATTENTION_SHOWN, 0),
            'link': {'label': link[0], 'sub': link[1]} if link else None}


def _age(hours: float | None) -> str:
    if hours is None:
        return 'never seen'
    if hours < 48:
        return f'{max(round(hours), 1)} hours'
    return f'{round(hours / 24)} days'


def _attention(report: rh.RuleHealthReport, systems: ds.SystemsReport, blind: object) -> list[dict[str, Any]]:
    rule_btn = lambda r: {'label': 'Open rule', 'fn': 'deOpenRule', 'arg': r.key}
    sys_btn = lambda sid: {'label': 'Open system', 'fn': 'deOpenSystem', 'arg': sid} if sid else None
    groups: list[dict[str, Any] | None] = []

    errors = []
    for r in report.rules:
        first = next((p for p in r.problems if p.level == 'error'), None)
        if first:
            errors.append(_row({'type': 'sev', 'value': r.severity}, r.name, f'{first.title} · {first.detail}'.strip(' ·'),
                               rule_btn(r), r.kind))
    groups.append(_group('error', 'Rule Monitoring errors' if report.monitoring == 'tide' else 'Rule errors',
                         'TIDE' if report.monitoring == 'tide' else 'ION', errors, ('Rules health', 'health')))

    kev = []
    for system in systems.systems:
        for v in system.kev or []:
            kev.append(_row({'type': 'kev'}, f"{v['cve']} {shorten(v.get('description') or v.get('package') or '', 72, placeholder='…')}".strip(),
                            f"{system.name} · {v.get('hosts') or 'unknown host'} · {v['severity'] or 'unrated'}",
                            sys_btn(system.id)))
    groups.append(_group('error', 'Known-exploited CVEs on systems', 'Wazuh vulnerability detector · CISA KEV', kev,
                         ('Systems', 'systems')))

    disabled = [_row({'type': 'sev', 'value': r.severity}, f'{r.name} is disabled',
                     ' · '.join(filter(None, [r.mitre_ids[0] if r.mitre_ids else None,
                                              f'quality {r.quality:.0f}' if r.quality is not None else 'unscored',
                                              f"GitLab #{r.gitlab[0]['iid']}: {r.gitlab[0]['title']}" if r.gitlab else 'no open issue explains why'])),
                     rule_btn(r), r.kind)
                for r in report.rules if not r.enabled and r.severity in ('critical', 'high')]
    groups.append(_group('warning', 'Disabled critical / high rules', 'TIDE', disabled))

    # ION's closures cannot tell destinations apart, so one rule id deployed
    # to two spaces is one noisy rule here.
    seen: set[str] = set()
    noisy = [r for r in sorted((r for r in report.rules if r.noisy), key=lambda r: -(r.outcome.fp_rate or 0))
             if not (r.rule_id in seen or seen.add(r.rule_id))]
    groups.append(_group('warning', 'Mostly closed as false positive', f'ION closures · {rh.CLOSURE_DAYS}d', [
        _row({'type': 'fp', 'value': round(r.outcome.fp_rate or 0)}, r.name,
             f'{r.outcome.false_positive} of {r.outcome.closed} closures were false positives'
             + (f' · {r.alerts:,} alerts / {rh.ALERT_WINDOW_DAYS}d' if r.alerts is not None else ''),
             rule_btn(r), r.kind) for r in noisy], ('Noise campaigns', 'health')))

    names = {s.id: s.name for s in systems.systems}
    groups.append(_group('warning', 'Disconnected Wazuh agents', 'Wazuh manager', [
        _row({'type': 'age', 'value': _age(a.age_hours), 'bad': a.age_hours is None or a.age_hours >= 24},
             f"{a.name} · {names.get(a.system_id, 'no system')}",
             f"{a.status.replace('_', ' ') or 'status unknown'} · {a.siem_id} / {a.space}", sys_btn(a.system_id))
        for a in systems.disconnected]))

    if isinstance(blind, list):
        groups.append(_group('info', 'Blind spots past their review date', 'accepted risk', [
            _row({'type': 'tag', 'value': b.get('override_type') or 'gap'}, f"{names.get(str(b.get('system_id')), 'All systems')}: {b.get('reason') or 'accepted blind spot'}",
                 f"Review was due {b.get('review_by')} · owner {b.get('created_by') or 'unknown'}",
                 {'label': 'Review', 'fn': 'deGo', 'arg': 'attack'}) for b in blind]))
    return [g for g in groups if g]


def _overview_reads(session: Session | None) -> tuple[PosturePanel, GapsPanel, ds.SystemsReport, object, int | None]:
    svc = get_tide_service()
    systems = ds.systems_report(svc, session, with_coverage=False, baselines=baseline_summaries(session))
    blind = svc.get_blind_spots_due() if svc.enabled else None
    playbooks = use_cases(session)
    return posture_view(session), gaps_view(session), systems, blind, len(playbooks) if playbooks is not None else None


def _open_requests(session: Session | None) -> int | None:
    from ion.web.de_api import tuning_requests_payload

    try:
        rows = tuning_requests_payload(session).get('requests')
    except Exception:
        logger.exception('Tuning requests could not be counted')
        return None
    return sum(1 for r in rows if isinstance(r, dict) and r.get('status') != 'closed') if isinstance(rows, list) else None


@router.get('/detection-engineering/overview', response_class=HTMLResponse)
async def overview(request: Request, session: Session = Depends(get_db_session),
                   user: User = Depends(get_current_user)):
    # One after the other: ION sheds TIDE queries past three in flight, and
    # these two reads together would trip it.
    report = await rh.cached_rule_health(session)
    posture, gaps, systems, blind, use_case_count = await run_in_threadpool(_overview_reads, session)
    open_requests = await run_in_threadpool(_open_requests, session) if user and user.has_permission('de:read') else None
    tactics = _tactic_rows(_blind_ids(gaps))
    attention = _attention(report, systems, blind)
    counts = report.problem_counts()
    rules = report.rules
    alerts = [r.alerts for r in rules if r.alerts is not None]
    series = [sum(r.days[i] for r in rules if r.days) for i in range(rh.ALERT_WINDOW_DAYS)] if alerts else None
    closures = report.closures
    kinds = {k: [r for r in rules if r.kind == k] for k in ('elastic', 'wazuh')}
    view = {
        'state': posture['state'] if report.state != 'failed' else 'failed', 'posture': posture,
        'failure': report.failure.as_dict() if report.failure else None,
        'coverage_pct': percent(posture['stats']['covered_techniques'], posture['stats']['total_techniques']),
        'tactics': [row for row in tactics or [] if row['covered']] if tactics is not None else None,
        'tactics_uncovered': sum(1 for row in tactics or [] if not row['covered']),
        'rules_total': len(rules) if report.state == 'data' else None,
        'rules_enabled': sum(r.enabled for r in rules),
        'by_kind': {k: {'enabled': sum(r.enabled for r in v), 'total': len(v)} for k, v in kinds.items()},
        'monitoring': report.monitoring, 'counts': counts,
        'closures': closures, 'closure_days': rh.CLOSURE_DAYS,
        'fp_rate': round(closures['fp'] / closures['closed'] * 100) if closures and closures['closed'] else None,
        'closure_segments': [{'cls': c, 'pct': round(closures[k] / closures['closed'] * 100, 1)}
                             for k, c in (('tp', 'o-tp'), ('fp', 'o-fp'), ('benign', 'o-bn'), ('other', 'o-ot')) if closures[k]]
                            if closures and closures['closed'] else [],
        'firing': sum(alerts) if alerts else None, 'firing_rules': sum(1 for a in alerts if a),
        'high_volume': sum(1 for a in alerts if a > rh.TOO_MANY_ALERTS), 'alert_days': rh.ALERT_WINDOW_DAYS,
        'firing_spark': spark_points(series, 90, 28) if series else None,
        'attention': attention, 'attention_total': sum(g['count'] for g in attention),
        'attention_errors': sum(g['count'] for g in attention if g['level'] == 'error' and g['title'] != 'Known-exploited CVEs on systems'),
        'attention_kev': sum(g['count'] for g in attention if g['title'] == 'Known-exploited CVEs on systems'),
        'attention_noisy': len({r.rule_id for r in rules if r.noisy}),
        'use_case_count': use_case_count, 'open_requests': open_requests,
        'systems': systems, 'notes': report.notes + systems.notes,
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


def _platforms(system_id: str) -> list[str] | None:
    rows = get_tide_service().get_system_platforms()
    if not isinstance(rows, list):
        return None
    row = next((r for r in rows if str(r.get('id')) == system_id), None)
    platforms = row.get('platforms') if row else None
    return [str(p) for p in platforms] if isinstance(platforms, list) and platforms else None


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
        'systems_coverage': gaps['systems_coverage'], 'platform_scope': None,
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
    if system_id:
        platforms = _platforms(system_id)
        applicable = ds.applicable_techniques(platforms)
        if applicable is not None:
            view['platform_scope'] = {'platforms': platforms, 'applicable': len(applicable)}
            for tactic in tactics:
                for cell in tactic['cells']:
                    cell['na'] = cell['id'] not in applicable
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
