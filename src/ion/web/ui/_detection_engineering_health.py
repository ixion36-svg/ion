"""Rules and Health: every rule with what is wrong with it, from rule_health_service.

The Rules table, the rule drawer and the Health panel all read one
RuleHealthReport, so a rule's alert count, its problems and its false-positive
rate are the same figure wherever they appear. Health folds in what Detection
Health and DE Metrics used to show: noise campaigns from ION closures, Bob's
agreement as its own tile, and MITRE's detection guidance for a rule.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.services import rule_health_service as rh
from ion.storage.database import get_db_session
from ion.web.ui._shared import render_view

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_permission('alert:read'))])

RULES_PAGE = 100
SEVERITIES = ('critical', 'high', 'medium', 'low')
CAMPAIGNS_SHOWN = 8
#: Closure outcomes as the Rules table draws them; anything else is "other".
OUTCOME_KEYS = (('tp', 'true_positive', 'TP'), ('fp', 'false_positive', 'FP'),
                ('bn', 'benign_true_positive', 'Benign'))


def spark_points(values: Optional[list[int]], width: int = 64, height: int = 18) -> Optional[str]:
    if not values or len(values) < 2:
        return None
    peak = max(values) or 1
    step = width / (len(values) - 1)
    return ' '.join(f'{i * step:.1f},{height - 1 - v / peak * (height - 3):.1f}' for i, v in enumerate(values))


def closure_view(rule: rh.RuleHealth) -> Optional[dict[str, Any]]:
    rec = rule.outcome
    if rec is None or not rec.closed:
        return None
    counts = {key: rec.outcomes.get(reason, 0) for key, reason, _ in OUTCOME_KEYS}
    counts['ot'] = rec.closed - sum(counts.values())
    return {
        'n': rec.closed, 'fp_rate': rec.fp_rate, 'noisy': rule.noisy,
        'segments': [{'cls': 'o-' + key, 'pct': round(counts[key] / rec.closed * 100, 1), 'n': counts[key]}
                     for key in ('tp', 'fp', 'bn', 'ot') if counts[key]],
        'counts': counts,
    }


def rule_view(rule: rh.RuleHealth) -> dict[str, Any]:
    loud = any(p.kind in ('noisy', 'alert_spike', 'too_many', 'spike') for p in rule.problems)
    return {
        'key': rule.key, 'rule_id': rule.rule_id, 'name': rule.name, 'kind': rule.kind,
        'severity': rule.severity if rule.severity in SEVERITIES else '', 'enabled': rule.enabled,
        'quality': rule.quality, 'mitre': (rule.mitre_ids or [''])[0], 'mitre_ids': rule.mitre_ids,
        'dest': rule.dest.label, 'alerts': rule.alerts,
        'spark': spark_points(rule.days),
        'spark_cls': 'bad' if loud else 'flat' if rule.alerts == 0 else '',
        'closures': closure_view(rule),
        'e': rule.count('error'), 'w': rule.count('warning'), 'i': rule.count('info'),
        'problems': [asdict(p) for p in sorted(rule.problems, key=lambda p: rh.LEVELS.index(p.level))],
        'gitlab': rule.gitlab, 'checks': rule.checks,
    }


@dataclass(frozen=True)
class RuleFilter:
    q: str = ''
    kind: str = ''
    severity: str = ''
    state: str = ''
    problems: bool = False

    def keep(self, rule: rh.RuleHealth) -> bool:
        if self.kind and rule.kind != self.kind:
            return False
        if self.severity and rule.severity != self.severity:
            return False
        if self.state in ('1', '0') and rule.enabled != (self.state == '1'):
            return False
        if self.problems and not rule.problems:
            return False
        if self.q:
            needle = self.q.lower()
            hay = ' '.join([rule.name, rule.rule_id, *rule.mitre_ids]).lower()
            return needle in hay
        return True


def _report_banner(report: rh.RuleHealthReport) -> dict[str, Any]:
    return {'state': report.state, 'failure': report.failure.as_dict() if report.failure else None,
            'notes': report.notes, 'monitoring': report.monitoring, 'alerts_from': report.alerts_from}


@router.get('/detection-engineering/rules', response_class=HTMLResponse)
async def rules_panel(request: Request, q: str = '', kind: str = '', severity: str = '', state: str = '',
                      problems: str = '', offset: int = Query(0, ge=0), body: str = '',
                      session: Session = Depends(get_db_session)):
    report = await rh.cached_rule_health(session)
    flt = RuleFilter(q=q.strip(), kind=kind if kind in ('elastic', 'wazuh') else '',
                     severity=severity if severity in SEVERITIES else '', state=state, problems=problems == '1')
    matched = [r for r in report.rules if flt.keep(r)]
    page = matched[offset:offset + RULES_PAGE]
    view = {
        **_report_banner(report), 'filter': asdict(flt), 'body_only': body == '1',
        'rules': [rule_view(r) for r in page], 'shown': len(matched), 'total': len(report.rules),
        'offset': offset, 'limit': RULES_PAGE,
    }
    return render_view(request, '_fragments/detection_engineering_rules.html', view)


@router.get('/detection-engineering/rules/drawer', response_class=HTMLResponse)
async def rule_drawer(request: Request, key: str = Query(..., max_length=400),
                      session: Session = Depends(get_db_session), user: User = Depends(get_current_user)):
    report = await rh.cached_rule_health(session)
    rule = report.by_key().get(key)
    history = None
    can_cases = bool(user and user.has_permission('case:read'))
    if rule is not None and rule.outcome is not None and can_cases:
        try:
            history = await run_in_threadpool(rh.recent_closures, session, rule.rule_id, rule.name)
        except Exception:
            logger.exception('Closure history could not be read for %s', key)
    view = {
        'state': 'data' if rule else 'missing' if report.state == 'data' else report.state,
        'rule': rule_view(rule) if rule else None, 'history': history, 'can_cases': can_cases,
        'can_propose': bool(user and user.has_permission('de:propose')),
        'closure_days': rh.CLOSURE_DAYS, 'alert_days': rh.ALERT_WINDOW_DAYS,
        'tide_url': _tide_url(),
    }
    return render_view(request, '_fragments/detection_engineering_rule_drawer.html', view)


def _tide_url() -> Optional[str]:
    from ion.services.tide_service import get_tide_service

    svc = get_tide_service()
    return svc.url or None if svc.enabled else None


def _group_problems(report: rh.RuleHealthReport) -> list[dict[str, Any]]:
    """One group per kind of problem, errors first, then the most affected."""
    groups: dict[str, dict[str, Any]] = {}
    for rule in report.rules:
        for p in rule.problems:
            g = groups.setdefault(p.kind, {'kind': p.kind, 'title': p.title, 'level': p.level, 'source': p.source,
                                           'why': rh.ION_PROBLEMS[p.kind][2] if p.kind in rh.ION_PROBLEMS else None,
                                           'rows': []})
            if rh.LEVELS.index(p.level) < rh.LEVELS.index(g['level']):
                g['level'] = p.level
            g['rows'].append({'rule': rule_view(rule), 'detail': p.detail, 'cause': p.cause})
    for d in report.destination_problems:
        p = d.problem
        g = groups.setdefault(p.kind, {'kind': p.kind, 'title': p.title, 'level': p.level, 'source': p.source,
                                       'why': None, 'rows': []})
        g['rows'].append({'dest': d.dest.label, 'detail': p.detail, 'cause': p.cause, 'gitlab': list(d.gitlab)})
    return sorted(groups.values(), key=lambda g: (rh.LEVELS.index(g['level']), -len(g['rows']), g['title']))


def _campaigns(session: Session) -> Optional[dict[str, Any]]:
    from ion.services.de_metrics_service import get_noise_campaigns

    try:
        return get_noise_campaigns(session, days=rh.CLOSURE_DAYS)
    except Exception:
        logger.exception('Noise campaigns could not be read')
        return None


def _bob_agreement(session: Session) -> Optional[dict[str, Any]]:
    from ion.services.de_bob_service import get_bob_scorecard

    try:
        card = get_bob_scorecard(session, days=rh.CLOSURE_DAYS)
    except Exception:
        logger.exception('Bob scorecard could not be read')
        return None
    return card if isinstance(card, dict) else None


@router.get('/detection-engineering/health', response_class=HTMLResponse)
async def health_panel(request: Request, session: Session = Depends(get_db_session),
                       user: User = Depends(get_current_user)):
    report = await rh.cached_rule_health(session)
    can_de = bool(user and user.has_permission('de:read'))
    campaigns = await run_in_threadpool(_campaigns, session) if can_de else None
    bob = await run_in_threadpool(_bob_agreement, session) if can_de else None
    counts = report.problem_counts()
    closures = report.closures
    rules = report.rules
    view = {
        **_report_banner(report), 'counts': counts, 'groups': _group_problems(report),
        'with_problems': sum(1 for r in rules if r.problems), 'total': len(rules),
        'with_problems_by_kind': {k: sum(1 for r in rules if r.problems and r.kind == k) for k in ('elastic', 'wazuh')},
        'silent': sum(1 for r in rules if any(p.kind == 'silent' for p in r.problems)),
        'closures': closures, 'closure_failed': report.closure_failed, 'closure_days': rh.CLOSURE_DAYS,
        'fp_rate': round(closures['fp'] / closures['closed'] * 100) if closures and closures['closed'] else None,
        'can_de': can_de, 'can_propose': bool(user and user.has_permission('de:propose')),
        'can_attack': bool(user and user.has_permission('security:read')),
        'campaigns': (campaigns or {}).get('campaigns', [])[:CAMPAIGNS_SHOWN] if campaigns else None,
        'campaign_summary': campaigns, 'bob': bob,
        'rule_keys': {r.name: r.key for r in rules},
    }
    return render_view(request, '_fragments/detection_engineering_health.html', view)


def attack_panel(payload: dict[str, Any]) -> dict[str, Any]:
    """unloaded (snapshot unreadable), untagged (alerts carry no technique),
    unmatched (techniques with no strategy) or ok: four answers, never merged."""
    snapshot = payload.get('snapshot') or {}
    techniques = payload.get('techniques') or []
    without = payload.get('techniques_without_guidance') or []
    if not snapshot.get('loaded'):
        state = 'unloaded'
    elif not techniques and not without:
        state = 'untagged'
    elif not techniques:
        state = 'unmatched'
    else:
        state = 'ok'
    return {
        'state': state, 'rule': payload.get('rule_name'), 'period_days': payload.get('period_days'),
        'attack_version': snapshot.get('attack_version'), 'alerts_seen': payload.get('alerts_seen'),
        'techniques': techniques, 'without_guidance': without, 'log_sources': payload.get('log_sources') or [],
        'analytic_total': sum(t.get('analytic_count') or 0 for t in techniques),
    }


@router.get('/detection-engineering/health/attack', response_class=HTMLResponse,
            dependencies=[Depends(require_permission('security:read'))])
def attack_guidance(request: Request, rule: str = Query(..., max_length=500), days: int = Query(90, ge=1, le=365),
                    session: Session = Depends(get_db_session)):
    from ion.services.rule_attack_guidance_service import get_rule_attack_guidance

    try:
        panel = attack_panel(get_rule_attack_guidance(session, rule, days=days))
        failed = False
    except Exception:
        logger.exception('ATT&CK guidance could not be read for rule %r', rule)
        panel, failed = None, True
    view = {'failed': failed, 'panel': panel, 'rule': rule}
    return render_view(request, '_fragments/detection_engineering_attack_guidance.html', view)
