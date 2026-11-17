"""Detection Engineering > Work: tuning requests, proposals, quirks and the content pack.

Every read is its own route so a failing store blanks only its own sub-view.
Reads need de:read, as the /api/de GETs do. Each control is drawn only for a
holder of the permission its /api/de write checks.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional, TypedDict

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import get_current_user, require_permission
from ion.models.bob_tuning_proposal import BobTuningProposalStatus
from ion.models.detection_proposal import DetectionProposalSource, DetectionProposalStatus
from ion.models.system_quirk import SystemQuirkStatus
from ion.models.user import User
from ion.storage.database import get_db_session
from ion.web.ui._shared import plain, render_view

logger = logging.getLogger(__name__)
router = APIRouter(dependencies=[Depends(require_permission('de:read'))])
State = Literal['failed', 'empty', 'data']


class Perms(TypedDict):
    propose: bool
    approve: bool
    verify: bool


def perms(user: Optional[User]) -> Perms:
    has = (lambda p: bool(user is not None and user.has_permission(p)))
    return {'propose': has('de:propose'), 'approve': has('de:approve'), 'verify': has('de:verify')}


def _now() -> datetime:
    # Naive UTC, which is what every DE column stores.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def parse_dt(raw: object) -> Optional[datetime]:
    if isinstance(raw, datetime):
        return raw.astimezone(timezone.utc).replace(tzinfo=None) if raw.tzinfo else raw
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed


def utc_iso(raw: object) -> Optional[str]:
    """A DE timestamp with its zone stated, so the ts macro can localise it.

    The columns are naive UTC. Handed over naive, the browser would read the
    digits as its own clock and an analyst at UTC+10 saw a lapsed quirk as
    still pending for ten hours.
    """
    parsed = parse_dt(raw)
    return None if parsed is None else parsed.replace(tzinfo=timezone.utc).isoformat()


def number(value: object) -> Optional[int | float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def num_text(value: object) -> Optional[str]:
    """How a figure prints: 0 stays "0", 12.0 is "12", None is no figure."""
    value = number(value)
    if value is None:
        return None
    if float(value).is_integer():
        return f'{int(value):,}'
    return f'{value:.2f}'.rstrip('0').rstrip('.')


def _str(value: object) -> Optional[str]:
    value = plain(value)
    return None if value is None else str(value)


def age_text(created: Optional[datetime], now: datetime) -> Optional[str]:
    if created is None or created > now:
        return None
    seconds = (now - created).total_seconds()
    if seconds >= 86400:
        return f'{int(seconds // 86400)}d'
    if seconds >= 3600:
        return f'{int(seconds // 3600)}h'
    return '<1h'


def _template(name: str) -> str:
    return f'_fragments/detection_engineering_work_{name}.html'


# ── Tuning requests ─────────────────────────────────────────────

REASON_LABELS = {
    'false_positive': 'False positive', 'noisy': 'Too noisy', 'threshold': 'Threshold wrong',
    'duplicate': 'Duplicate', 'other': 'Other',
}
REQUEST_TAG = {'open': '', 'triaged': 'warn', 'linked': 'accent'}
# de_tuning_request_service refuses triage unless open, and link/close once closed.
REQUEST_ACTIONS = {
    'open': [('dwTriage', 'Triage'), ('dwDraftForRequest', 'Draft proposal'), ('dwClose', 'Close')],
    'triaged': [('dwDraftForRequest', 'Draft proposal'), ('dwClose', 'Close')],
    'linked': [('dwDraftForRequest', 'Draft proposal'), ('dwClose', 'Close')],
    'closed': [],
}


def request_row(raw: dict[str, Any], now: datetime, usernames: dict[int, str], can_propose: bool) -> dict[str, Any]:
    status = _str(raw.get('status'))
    reason = _str(raw.get('reason'))
    created = parse_dt(raw.get('created_at'))
    evidence = raw.get('evidence_json') if isinstance(raw.get('evidence_json'), dict) else {}
    details = raw.get('details')
    rid = raw.get('id')
    return {
        'id': rid,
        'reason': REASON_LABELS.get(reason, reason),
        'details': str(details)[:160] if details else None,
        'rule_name': raw.get('rule_name'),
        'raised_by': usernames.get(raw.get('requested_by_id')),
        'status': status,
        'status_tag': REQUEST_TAG.get(status, ''),
        'gitlab_url': raw.get('gitlab_issue_url'),
        'gitlab_iid': raw.get('gitlab_issue_iid'),
        'created_at': utc_iso(created),
        'age': age_text(created, now),
        'fp_7d': number(evidence.get('fp_alerts_7d')),
        'actions': [{'action': a, 'label': label, 'args': [rid, raw.get('rule_name')]}
                    for a, label in REQUEST_ACTIONS.get(status, [])] if can_propose and rid is not None else [],
    }


def requests_view(payload: object, usernames: dict[int, str], can_propose: bool) -> dict[str, Any]:
    raw = payload.get('requests') if isinstance(payload, dict) else None
    if not isinstance(raw, list):
        return {'state': 'failed', 'rows': None, 'count': None}
    now = _now()
    rows = [request_row(r, now, usernames, can_propose)
            for r in raw if isinstance(r, dict) and _str(r.get('status')) != 'closed']
    return {'state': 'data' if rows else 'empty', 'rows': rows, 'count': len(rows)}


def _usernames(session: Session, payload: object) -> dict[int, str]:
    raw = payload.get('requests') if isinstance(payload, dict) else None
    ids = {r.get('requested_by_id') for r in raw or [] if isinstance(r, dict)}
    ids.discard(None)
    if not ids:
        return {}
    return dict(session.query(User.id, User.username).filter(User.id.in_(ids)).all())


@router.get('/detection-engineering/work/requests', response_class=HTMLResponse)
def work_requests(request: Request, user: User = Depends(get_current_user),
                  session: Session = Depends(get_db_session)):
    from ion.web.de_api import tuning_requests_payload
    try:
        payload = tuning_requests_payload(session)
        view = requests_view(payload, _usernames(session, payload), perms(user)['propose'])
    except Exception:
        logger.exception('Tuning requests could not be read')
        view = {'state': 'failed', 'rows': None, 'count': None}
    return render_view(request, _template('requests'), view)


# ── Proposals: detection proposals and Bob tuning proposals in one table ──

Source = Literal['bob', 'analyst']
SourceFilter = Literal['all', 'bob', 'analyst', 'human']

DETECTION_TAG = {'draft': '', 'applied': 'ok', 'rejected': 'bad', 'duplicate': ''}
BOB_TAG = {'draft': '', 'approved': 'ok', 'rejected': 'bad', 'reverted': 'warn'}
# Keyed by status so a new enum member is a missing key (a test failure),
# not a row that silently offers nothing. The service refuses edit/decide
# unless draft and measure unless applied; Bob approve/reject need draft and
# revert needs approved.
DETECTION_ACTIONS = {
    DetectionProposalStatus.DRAFT.value: [('dpEdit', 'Edit', None), ('dpDecide', 'Apply', 'applied'), ('dpDecide', 'Reject', 'rejected')],
    DetectionProposalStatus.APPLIED.value: [('dpMeasure', 'Measure outcome', None)],
    DetectionProposalStatus.REJECTED.value: [],
    DetectionProposalStatus.DUPLICATE.value: [],
}
BOB_ACTIONS = {
    BobTuningProposalStatus.DRAFT.value: [('bbApprove', 'Approve'), ('bbReject', 'Reject')],
    BobTuningProposalStatus.APPROVED.value: [('bbRevert', 'Revert')],
    BobTuningProposalStatus.REJECTED.value: [],
    BobTuningProposalStatus.REVERTED.value: [],
}


def outcome_effect(status: Optional[str], outcome: object) -> Optional[dict[str, Any]]:
    """The measured effect of an applied proposal, or None when there is none to state.

    Only the equal-window `comparable.drop_pct` is quoted. The top-level
    drop_pct divides a full baseline by however little time has passed since
    the change and flatters one that landed yesterday.
    """
    if not isinstance(outcome, dict):
        return {'text': 'not yet measured', 'tag': ''} if status == 'applied' else None
    comparable = outcome.get('comparable')
    if not isinstance(comparable, dict):
        return {'text': 'legacy measurement, re-measure', 'tag': 'warn'}
    before, after = comparable.get('before_count'), comparable.get('after_count')
    window = num_text(comparable.get('window_days_exact'))
    detail = f'{num_text(before) or "?"} → {num_text(after) or "?"} FP over matched {window or "?"}d windows'
    sufficient, drop = comparable.get('sufficient_observation'), number(comparable.get('drop_pct'))
    threats = outcome.get('confirmed_threats')
    lost = isinstance(threats, dict) and threats.get('lost_confirmed_threats') is True
    if sufficient is True and drop is not None:
        sign = '−' if drop >= 0 else '+'
        return {'text': f'{sign}{num_text(abs(drop))}% FP (measured)', 'tag': 'ok', 'title': detail, 'lost': lost}
    if sufficient is False:
        return {'text': 'not enough observation yet', 'tag': '', 'title': detail, 'lost': lost}
    if sufficient is True:
        return {'text': 'no baseline to quote a %', 'tag': '', 'title': detail, 'lost': lost}
    return {'text': 'comparable window not judged', 'tag': '', 'title': detail, 'lost': lost}


def detection_row(p: dict[str, Any], perm: Perms) -> dict[str, Any]:
    status = _str(p.get('status'))
    pid = p.get('id')
    actions = list(DETECTION_ACTIONS.get(status, []))
    # measure_outcome refuses a proposal with no rule or no applied_at.
    if not p.get('rule_name') or p.get('applied_at') is None:
        actions = [a for a in actions if a[0] != 'dpMeasure']
    fp, hours = number(p.get('expected_fp_reduction')), number(p.get('expected_hours_reclaimed'))
    forecast = None
    if fp is not None:
        forecast = f'−{num_text(fp)} FP (est.)' + (f' · {num_text(hours)}h' if hours is not None else '')
    source = _str(p.get('source'))
    return {
        'kind': 'detection',
        'id': pid,
        'source': 'bob' if source == DetectionProposalSource.BOB.value else 'analyst',
        'title': p.get('title') or '',
        'detail': p.get('suggested_change'),
        'change_type': _str(p.get('change_type')),
        'rule_name': p.get('rule_name'),
        'status': status,
        'status_tag': DETECTION_TAG.get(status, ''),
        'effect': outcome_effect(status, p.get('outcome')),
        'forecast': forecast,
        'by': p.get('created_by_username') or ('Bob' if source == DetectionProposalSource.BOB.value else None),
        'decided_by': p.get('decided_by_username'),
        'created_at': utc_iso(p.get('created_at')),
        'actions': [{'action': a, 'label': label, 'args': [pid, decision] if decision else [pid]}
                    for a, label, decision in actions] if perm['propose'] and pid is not None else [],
    }


def bob_row(p: dict[str, Any], perm: Perms) -> dict[str, Any]:
    status = _str(p.get('status'))
    pid = p.get('id')
    evidence = p.get('evidence_backed') is True
    return {
        'kind': 'bob_tuning',
        'id': pid,
        'source': 'bob',
        'title': p.get('title') or '',
        'detail': p.get('problem_statement'),
        'change_type': 'Bob prompt',
        'rule_name': p.get('rule_name'),
        'status': status,
        'status_tag': BOB_TAG.get(status, ''),
        'effect': {'text': 'evaluation-backed', 'tag': 'ok'} if evidence else None,
        'forecast': None,
        'by': p.get('created_by_username'),
        'decided_by': p.get('decided_by_username') or p.get('reverted_by_username'),
        'created_at': utc_iso(p.get('created_at')),
        'actions': [{'action': a, 'label': label, 'args': [pid, evidence] if a == 'bbApprove' else [pid]}
                    for a, label in BOB_ACTIONS.get(status, [])] if perm['approve'] and pid is not None else [],
    }


def proposals_view(detection: Optional[list], bob: Optional[list], source: Source | Literal['all'],
                   perm: Perms) -> dict[str, Any]:
    """None for a list is a failed read; it is named in `failed` and never counted as zero."""
    failed = [name for name, rows in (('detection proposals', detection), ('Bob tuning proposals', bob))
              if rows is None]
    rows = [detection_row(p, perm) for p in detection or [] if isinstance(p, dict)]
    rows += [bob_row(p, perm) for p in bob or [] if isinstance(p, dict)]
    rows.sort(key=lambda r: r['created_at'] or '', reverse=True)
    state: State = 'data' if rows else 'failed' if failed else 'empty'
    complete = not failed
    return {
        'state': state, 'source': source, 'failed': failed, 'rows': rows,
        'count': len(rows) if complete else None,
        'bob_count': sum(r['source'] == 'bob' for r in rows) if complete else None,
        'can_propose': perm['propose'],
    }


@router.get('/detection-engineering/work/proposals', response_class=HTMLResponse)
def work_proposals(request: Request, source: SourceFilter = Query('all'),
                   user: User = Depends(get_current_user), session: Session = Depends(get_db_session)):
    from ion.services import de_bob_proposal_service, de_proposal_service
    wanted = 'analyst' if source == 'human' else source
    detection: Optional[list] = None
    bob: Optional[list] = []
    try:
        detection = de_proposal_service.list_proposals(
            session, source={'all': 'all', 'bob': 'bob', 'analyst': 'human'}[wanted])
    except Exception:
        logger.exception('Detection proposals could not be read')
    # Bob tuning proposals are all Bob's, so an analyst filter skips the read.
    if wanted != 'analyst':
        try:
            bob = de_bob_proposal_service.list_proposals(session, status='all')
        except Exception:
            logger.exception('Bob tuning proposals could not be read')
            bob = None
    return render_view(request, _template('proposals'), proposals_view(detection, bob, wanted, perms(user)))


# ── Quirks ──────────────────────────────────────────────────────

QUIRK_TAG = {'pending': 'warn', 'active': 'ok', 'reverted': ''}
# verify_quirk refuses anything not pending; revert_quirk refuses reverted.
QUIRK_ACTIONS = {
    SystemQuirkStatus.PENDING.value: [('dwVerifyQuirk', 'Verify'), ('dwRevertQuirk', 'Revert')],
    SystemQuirkStatus.ACTIVE.value: [('dwRevertQuirk', 'Revert')],
    SystemQuirkStatus.REVERTED.value: [],
}
REVIEW_SOON = timedelta(days=7)


def scope_chips(q: dict[str, Any]) -> list[str]:
    chips = [f'{prefix}:{v}' for prefix, key in (('rule', 'scope_rules'), ('host', 'scope_hosts'),
             ('user', 'scope_users'), ('ip', 'scope_ips')) for v in (q.get(key) or [])]
    chips += [f"{o.get('type') or ''}:{o.get('value') or ''}" for o in q.get('scope_observables') or []
              if isinstance(o, dict)]
    return chips


def review_text(status: Optional[str], expired: object, review: Optional[datetime], now: datetime) -> Optional[str]:
    """How far off a review is. `expired` is SystemQuirk.is_expired(), the engine's own answer."""
    if review is None or status == 'reverted':
        return None
    if expired is True:
        return 'lapsed'
    remaining = (review - now).total_seconds()
    if remaining <= 0:
        return 'due now'
    if remaining >= 86400:
        return f'in {int(remaining // 86400)}d'
    if remaining >= 3600:
        return f'in {int(remaining // 3600)}h'
    return 'in <1h'


def quirk_row(q: dict[str, Any], now: datetime, perm: Perms) -> dict[str, Any]:
    status = _str(q.get('status'))
    review = parse_dt(q.get('review_date'))
    qid = q.get('id')
    lapsed = status == 'active' and q.get('expired') is True
    due_soon = status != 'reverted' and review is not None and not lapsed and review - now < REVIEW_SOON
    return {
        'id': qid,
        'title': q.get('title') or '',
        'annotation': q.get('annotation'),
        'scope': scope_chips(q),
        'review_date': utc_iso(review),
        'review_text': review_text(status, q.get('expired'), review, now),
        'review_tag': 'bad' if lapsed else 'warn' if due_soon else '',
        'status': status,
        'status_tag': QUIRK_TAG.get(status, ''),
        'raised_by': q.get('raised_by_username'),
        'verified_by': q.get('verified_by_username'),
        'actions': [{'action': a, 'label': label, 'args': [qid]} for a, label in QUIRK_ACTIONS.get(status, [])]
                   if perm['verify'] and qid is not None else [],
    }


def quirks_view(raw: object, perm: Perms) -> dict[str, Any]:
    if not isinstance(raw, list):
        return {'state': 'failed', 'rows': None, 'count': None, 'can_propose': perm['propose']}
    now = _now()
    rows = [quirk_row(q, now, perm) for q in raw if isinstance(q, dict)]
    live = sum(r['status'] != 'reverted' for r in rows)
    return {'state': 'data' if rows else 'empty', 'rows': rows, 'count': live, 'can_propose': perm['propose']}


@router.get('/detection-engineering/work/quirks', response_class=HTMLResponse)
def work_quirks(request: Request, user: User = Depends(get_current_user),
                session: Session = Depends(get_db_session)):
    from ion.services.de_quirk_service import list_quirks
    try:
        raw: object = list_quirks(session, status='all')
    except Exception:
        logger.exception('System quirks could not be read')
        raw = None
    return render_view(request, _template('quirks'), quirks_view(raw, perms(user)))


# ── Content pack ────────────────────────────────────────────────

def content_pack_view(perm: Perms) -> dict[str, Any]:
    return {'can_import': perm['propose']}


@router.get('/detection-engineering/work/content-pack', response_class=HTMLResponse)
def work_content_pack(request: Request, user: User = Depends(get_current_user)):
    """Reads nothing; it exists so Import is withheld from non-de:propose viewers."""
    return render_view(request, _template('content_pack'), content_pack_view(perms(user)))
