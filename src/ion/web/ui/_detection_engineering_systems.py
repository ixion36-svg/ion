"""Systems: each TIDE system's platforms, coverage, CVEs, CIS hardening, Wazuh
agents and log source freshness, and ION's log source register (what was the
Log Source Health page) with its create, edit, delete and seed actions."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.services import attack_catalogue, log_source_service
from ion.services import de_systems_service as ds
from ion.services import rule_health_service as rh
from ion.services.tide_service import get_tide_service
from ion.storage.database import get_db_session
from ion.web.ui._detection_engineering_health import rule_health_for, spark_points
from ion.web.ui._shared import render_view

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_permission('alert:read'))])

GAPS_SHOWN = 8
FAILING_SHOWN = 6


def _register(session: Session) -> Optional[list[dict]]:
    try:
        return log_source_service.list_sources(session)
    except Exception:
        logger.exception('Log source register could not be read')
        return None


async def _register_health(session: Session, registry: Optional[list[dict]]) -> Optional[dict]:
    if not registry:
        return None
    try:
        return await log_source_service.check_all(session)
    except Exception:
        logger.exception('Log source health check could not be run')
        return None


def _register_rows(registry: Optional[list[dict]], health: Optional[dict]) -> Optional[list[dict]]:
    if registry is None:
        return None
    checked = {row.get('id'): row for row in (health or {}).get('sources') or []}
    rows = []
    for src in registry:
        check = checked.get(src.get('id'))
        last = ds._when((check or src).get('last_event_at'))
        age = (ds._utcnow() - last).total_seconds() / 3600 if last else None
        status = (check or {}).get('status') or src.get('last_status')
        rows.append({
            'id': src.get('id'), 'name': src.get('name'), 'category': src.get('category'),
            'tags': src.get('tags') or [], 'enabled': src.get('enabled', True),
            'criticality': src.get('criticality'), 'age': age,
            'fresh': ds.freshness_state(age, int(src.get('expected_interval_minutes') or 60)) if status not in ('error',) else 'bad',
            'status': status or ('never' if last is None else None), 'cached': bool((check or {}).get('cached')),
        })
    return rows


def age_text(hours: Optional[float]) -> str:
    if hours is None:
        return 'never'
    if hours < 1:
        return f'{max(round(hours * 60), 1)}m'
    if hours < 48:
        return f'{round(hours)}h'
    return f'{round(hours / 24)}d'


def _cis_view(system: ds.SystemProfile) -> Optional[dict[str, Any]]:
    if system.cis_score is None:
        return None
    trend = system.cis_trend or []
    delta = round(trend[-1] - trend[0]) if len(trend) >= 2 else None
    return {'score': system.cis_score, 'delta': delta, 'spark': spark_points(trend, 92, 26) if len(trend) >= 2 else None,
            'up': delta is None or delta >= 0, 'weeks': len(trend), 'policies': system.cis_policies or []}


def system_view(system: ds.SystemProfile) -> dict[str, Any]:
    agents = system.agents
    return {
        'id': system.id, 'name': system.name, 'platforms': system.platforms,
        'coverage_pct': system.coverage_pct, 'covered': system.covered, 'applicable': system.applicable,
        'baseline_pct': system.baseline_pct, 'baseline_covered': system.baseline_covered,
        'baseline_total': system.baseline_total,
        'vulns': system.vulns, 'vuln_total': system.vuln_total, 'kev': system.kev, 'cves': system.cves,
        'cis': _cis_view(system),
        'agents': [{'name': a.name, 'cls': 'never' if a.status == 'never_connected' else '' if a.connected else 'disc',
                    'age': age_text(a.age_hours), 'status': a.status} for a in agents] if agents is not None else None,
        'agents_active': sum(1 for a in agents or [] if a.connected),
        'freshness': [{'name': f.name, 'age': age_text(f.age_hours), 'state': f.state, 'source': f.source}
                      for f in sorted(system.freshness, key=lambda f: ('ok', 'warn', 'bad', 'unknown').index(f.state), reverse=True)],
        'failing': system.failing_checks,
    }


def _gaps(system: ds.SystemProfile, report: rh.RuleHealthReport) -> Optional[list[dict[str, Any]]]:
    applicable = ds.applicable_techniques(system.platforms)
    if system.covered_ids is None:
        return None
    names = {t['technique_id']: t for t in attack_catalogue.techniques()}
    by_tech: dict[str, list[rh.RuleHealth]] = {}
    for rule in report.rules:
        for tid in rule.mitre_ids:
            by_tech.setdefault(tid, []).append(rule)
    gaps = []
    for tid in sorted((applicable or set(names)) - system.covered_ids):
        rules = by_tech.get(tid, [])
        broken = next((p for r in rules for p in r.problems if p.level == 'error'), None)
        if broken:
            why, cls = broken.title, 'bad'
        elif any(r.noisy for r in rules):
            why, cls = 'mostly FP', 'warn'
        elif rules and not any(r.enabled for r in rules):
            why, cls = 'rule disabled', 'warn'
        elif rules:
            why, cls = 'rule not applied here', 'warn'
        else:
            why, cls = 'no rule', 'bad'
        gaps.append({'id': tid, 'name': names.get(tid, {}).get('name'), 'tactic': names.get(tid, {}).get('tactic'),
                     'why': why, 'cls': cls, 'weight': 0 if rules else 1})
    gaps.sort(key=lambda g: (g['weight'], g['id']))
    return gaps


def baseline_summaries(session: Optional[Session]) -> Optional[dict]:
    """Each system's baseline coverage, from the sync snapshot when it is
    current for the destination scope, else live."""
    from ion.web import de_tide_api

    svc = get_tide_service()
    try:
        found = de_tide_api._snapshot_or_live(session, 'system_baselines', svc.get_system_baseline_summaries)
    except Exception:
        logger.exception('System baseline coverage could not be read')
        return None
    return found if isinstance(found, dict) else None


def _systems(session: Session, register: Optional[list[dict]]) -> ds.SystemsReport:
    return ds.systems_report(get_tide_service(), session, register=register, baselines=baseline_summaries(session))


@router.get('/detection-engineering/systems', response_class=HTMLResponse)
async def systems_panel(request: Request, system_id: str = '', session: Session = Depends(get_db_session),
                        user: User = Depends(get_current_user)):
    registry = await run_in_threadpool(_register, session)
    report, health = await asyncio.gather(run_in_threadpool(_systems, session, registry),
                                          _register_health(session, registry))
    systems = [system_view(s) for s in report.systems if not system_id or s.id == system_id]
    view = {
        'state': report.state, 'failure': report.failure.as_dict() if report.failure else None,
        'notes': report.notes, 'systems': systems, 'has_assets': report.has_assets, 'scoped': bool(system_id),
        'register': _register_rows(registry, health), 'es_configured': (health or {}).get('es_configured'),
        'can_manage': bool(user and user.has_permission('integration:manage')),
        'system_names': [s.name for s in report.systems],
    }
    return render_view(request, '_fragments/detection_engineering_systems.html', view)


@router.get('/detection-engineering/systems/{system_id}', response_class=HTMLResponse)
async def system_detail(request: Request, system_id: str, session: Session = Depends(get_db_session),
                        user: User = Depends(get_current_user)):
    registry = await run_in_threadpool(_register, session)
    rules = await rule_health_for(session, user)
    report = await run_in_threadpool(_systems, session, registry)
    system = report.get(system_id)
    gaps = _gaps(system, rules) if system else None
    view = {
        'state': report.state if system or report.state != 'data' else 'missing',
        'failure': report.failure.as_dict() if report.failure else None, 'notes': report.notes,
        'system': system_view(system) if system else None,
        'gaps': gaps[:GAPS_SHOWN] if gaps else gaps, 'gaps_more': max(len(gaps or []) - GAPS_SHOWN, 0),
        'failing_shown': FAILING_SHOWN,
    }
    return render_view(request, '_fragments/detection_engineering_system_detail.html', view)
