"""Detection Engineering > Bob: scorecard, disagreements and the abuse monitor.

Bob agreement is how often Bob's verdict matched the analyst's closure. It is
not a false-positive rate and nothing here mixes the two.
"""
from __future__ import annotations

import logging
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._detection_engineering_work import number, perms
from ion.web.ui._shared import plain, render_view

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_permission('de:read'))])
State = Literal['failed', 'empty', 'data']

DAYS = 90
MIN_VERDICTS = 20


def _template(name: str) -> str:
    return f'_fragments/detection_engineering_bob_{name}.html'


def _read(label: str, fn, *args, **kwargs) -> Any:
    try:
        return fn(*args, **kwargs)
    except Exception:
        logger.exception('%s could not be read', label)
        return None


def scorecard_tiles(card: object) -> Optional[dict[str, Any]]:
    summary = card.get('summary') if isinstance(card, dict) else None
    if not isinstance(summary, dict):
        return None
    drift = summary.get('drift') if isinstance(summary.get('drift'), dict) else {}
    few = summary.get('few_shot') if isinstance(summary.get('few_shot'), dict) else {}
    enabled = few.get('gold_exemplar_retrieval_enabled')
    direction = plain(drift.get('direction'))
    return {
        'agreement_rate': number(summary.get('agreement_rate')),
        'agreed': number(summary.get('agreed')),
        'scored': number(summary.get('scored')),
        'disagreements': number(summary.get('total_disagreements')),
        'classes': number(summary.get('disagreement_classes')),
        'drift_delta': number(drift.get('delta')),
        'drift_direction': str(direction) if direction else None,
        'few_shot_enabled': enabled if isinstance(enabled, bool) else None,
        'few_shot_note': few.get('note') if isinstance(few.get('note'), str) else '',
    }


def accepted_tile(bob_drafted: object) -> Optional[dict[str, int]]:
    """Detection proposals Bob drafted, and how many an analyst applied."""
    if not isinstance(bob_drafted, list):
        return None
    applied = sum(1 for p in bob_drafted if isinstance(p, dict) and plain(p.get('status')) == 'applied')
    return {'applied': applied, 'total': len(bob_drafted)}


def by_rule_rows(payload: object) -> Optional[list[dict[str, Any]]]:
    rules = payload.get('rules') if isinstance(payload, dict) else None
    if not isinstance(rules, list):
        return None
    return [{'rule_name': r.get('rule_name'), 'rate': number(r.get('agreement_rate')),
             'scored': number(r.get('scored')), 'disagreed': number(r.get('disagreed'))}
            for r in rules if isinstance(r, dict)]


def scorecard_view(card: object, bob_drafted: object, by_rule: object) -> dict[str, Any]:
    tiles = scorecard_tiles(card)
    rules = by_rule_rows(by_rule)
    return {
        'state': 'failed' if tiles is None else 'empty' if tiles['scored'] == 0 else 'data',
        'days': DAYS,
        'tiles': tiles,
        'accepted': accepted_tile(bob_drafted),
        'rules_state': 'failed' if rules is None else 'data' if rules else 'empty',
        'rules': rules,
        'min_verdicts': MIN_VERDICTS,
        'below_minimum': number(by_rule.get('below_minimum')) if isinstance(by_rule, dict) else None,
    }


@router.get('/detection-engineering/bob/scorecard', response_class=HTMLResponse)
def bob_scorecard(request: Request, session: Session = Depends(get_db_session)):
    from ion.services import de_bob_service, de_proposal_service
    view = scorecard_view(
        _read('Bob scorecard', de_bob_service.get_bob_scorecard, session, days=DAYS),
        _read('Bob-drafted proposals', de_proposal_service.list_proposals, session, source='bob', limit=1000),
        _read('Bob agreement by rule', de_bob_service.get_agreement_by_rule, session, days=DAYS,
              min_verdicts=MIN_VERDICTS),
    )
    return render_view(request, _template('scorecard'), view)


def disagreement_row(c: dict[str, Any], can_propose: bool) -> dict[str, Any]:
    reasons = c.get('sample_reasons')
    rule, bob_v, human_v = c.get('rule_name'), c.get('bob_verdict'), c.get('human_verdict')
    return {
        'rule_name': rule, 'bob_verdict': bob_v, 'human_verdict': human_v,
        'count': number(c.get('count')),
        # A string is iterable, and walking it would print one letter per line.
        'reasons': [str(r) for r in reasons if r is not None] if isinstance(reasons, list) else [],
        'draft_args': [rule, bob_v, human_v] if can_propose else None,
    }


def disagreements_view(feedback: object, can_propose: bool) -> dict[str, Any]:
    classes = feedback.get('classes') if isinstance(feedback, dict) else None
    if not isinstance(classes, list):
        return {'state': 'failed', 'rows': None, 'total': None, 'days': DAYS, 'can_propose': can_propose}
    rows = [disagreement_row(c, can_propose) for c in classes if isinstance(c, dict)]
    return {
        'state': 'data' if rows else 'empty', 'rows': rows, 'days': DAYS, 'can_propose': can_propose,
        'total': number(feedback.get('total_disagreements')),
    }


@router.get('/detection-engineering/bob/disagreements', response_class=HTMLResponse)
def bob_disagreements(request: Request, user: User = Depends(get_current_user),
                      session: Session = Depends(get_db_session)):
    from ion.services.de_bob_service import get_bob_feedback
    feedback = _read('Bob feedback', get_bob_feedback, session, days=DAYS)
    return render_view(request, _template('disagreements'), disagreements_view(feedback, perms(user)['propose']))


def abuse_view(scan: object, days: int) -> dict[str, Any]:
    signals = scan.get('signals') if isinstance(scan, dict) else None
    if not isinstance(signals, list):
        return {'state': 'failed', 'days': days, 'signals': None, 'high': None, 'medium': None}
    rows = []
    for s in signals:
        if not isinstance(s, dict):
            continue
        kind = s.get('type')
        count = f"{s.get('rule_count')} rules" if kind == 'broad_scope_quirk' else s.get('count')
        rows.append({'severity': s.get('severity'), 'type': kind, 'description': s.get('description'),
                     'count': count})
    by_sev = (scan.get('summary') or {}).get('by_severity') if isinstance(scan.get('summary'), dict) else None
    by_sev = by_sev if isinstance(by_sev, dict) else {}
    return {
        'state': 'data' if rows else 'empty', 'days': days, 'signals': rows,
        'high': number(by_sev.get('high')), 'medium': number(by_sev.get('medium')),
    }


@router.get('/detection-engineering/bob/abuse', response_class=HTMLResponse,
            dependencies=[Depends(require_permission('de:verify'))])
def bob_abuse(request: Request, days: int = Query(DAYS, ge=1, le=365),
              session: Session = Depends(get_db_session)):
    from ion.services.de_abuse_service import scan_abuse
    return render_view(request, _template('abuse'), abuse_view(_read('DE abuse scan', scan_abuse, session, days=days), days))
