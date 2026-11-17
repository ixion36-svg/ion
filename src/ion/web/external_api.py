"""Read-only endpoints for machine clients outside ION, versioned under /api/external/v1.

TIDE pulls per-rule closure outcomes from here, the way ION pulls rules from
TIDE's /api/external/query. The caller authenticates the way every ION machine
client does: a service account's bearer token, ``Authorization: Bearer <token>``,
minted by ``ion seed-tide``. The route also demands that the caller is a service
account holding ``rule_outcomes:read``; the seeded ``tide`` role holds that and
nothing else, so a leaked token reads closure counts and no other ION data.

The schema carries counts and outcomes only. ``RuleOutcome`` holds no analyst,
note, host or alert id, and the response models below are the allowlist of
what leaves: a field added to the record does not reach TIDE until it is
added here.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import audit_refusal, require_permission
from ion.models.user import User
from ion.services.rule_outcome_service import (
    DEFAULT_WINDOW_DAYS,
    OUTCOMES,
    NoisyPolicy,
    RuleOutcome,
    Window,
    rule_outcomes,
    utcnow,
)
from ion.storage.database import get_db_session
from ion.web.api import limiter

router = APIRouter(prefix="/external/v1", tags=["external"])

PERMISSION = "rule_outcomes:read"
SCHEMA = "ion.rule_outcomes.v1"
MAX_LIMIT = 500


def require_service_caller(
    request: Request, user: User = Depends(require_permission(PERMISSION)),
) -> User:
    """A service account holding PERMISSION; a human's session is refused.

    Admins hold every permission, so the permission alone would let any admin
    session in. This surface is for integrations, and keeping humans off it
    keeps its audit trail to the accounts minted for it.
    """
    if not getattr(user, "is_service_account", False):
        audit_refusal("permission_denied", user, request, required="service account")
        raise HTTPException(status_code=403, detail="Permission denied")
    return user


class NoisyPolicyOut(BaseModel):
    min_closed: int
    fp_rate_pct: float


class WindowOut(BaseModel):
    since: datetime
    until: datetime


class RuleOutcomeOut(BaseModel):
    rule_id: Optional[str]
    rule_name: str
    rule_uuids: List[str]
    alerts: int
    closed: int
    outcomes: Dict[str, int]
    fp_rate_pct: Optional[float]
    tp_yield_pct: Optional[float]
    median_seconds_to_close: Optional[int]
    last_closed_at: Optional[datetime]
    noisy: bool


class RuleOutcomesPage(BaseModel):
    schema_version: str
    window: WindowOut
    noisy_policy: NoisyPolicyOut
    outcome_keys: List[str]
    items: List[RuleOutcomeOut]
    next_cursor: Optional[str]


def _bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


def _parse_instant(value: Optional[str], name: str) -> Optional[datetime]:
    """ISO 8601 to naive UTC. A value without an offset is read as UTC."""
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise _bad_request(f"{name} must be an ISO 8601 timestamp")
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _window(since: Optional[str], until: Optional[str]) -> Window:
    end = _parse_instant(until, "until") or utcnow()
    start = _parse_instant(since, "since") or end - timedelta(days=DEFAULT_WINDOW_DAYS)
    try:
        return Window(since=start, until=end)
    except ValueError as exc:
        raise _bad_request(str(exc))


def _utc(value: Optional[datetime]) -> Optional[datetime]:
    """Stored naive UTC, labelled as UTC so a client reads it without guessing."""
    return value.replace(tzinfo=timezone.utc) if value is not None else None


def _encode_cursor(token: str) -> str:
    return base64.urlsafe_b64encode(token.encode("utf-8")).decode("ascii")


def _decode_cursor(cursor: str) -> str:
    try:
        return base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeError, ValueError):
        raise _bad_request("cursor is not one this endpoint issued")


def _item(rec: RuleOutcome, policy: NoisyPolicy) -> RuleOutcomeOut:
    return RuleOutcomeOut(
        rule_id=rec.key.rule_id,
        rule_name=rec.rule_name,
        rule_uuids=sorted(rec.rule_uuids),
        alerts=rec.alerts,
        closed=rec.closed,
        outcomes=dict(rec.outcomes),
        fp_rate_pct=rec.fp_rate,
        tp_yield_pct=rec.tp_yield,
        median_seconds_to_close=rec.median_seconds_to_close,
        last_closed_at=_utc(rec.last_closed_at),
        noisy=policy.is_noisy(rec),
    )


@router.get(
    "/rule-outcomes",
    response_model=RuleOutcomesPage,
    dependencies=[Depends(require_service_caller)],
)
@limiter.limit("60/minute")
def list_rule_outcomes(
    request: Request,
    since: Optional[str] = Query(None, max_length=64, description="Window start, ISO 8601 (default: until minus 90 days)"),
    until: Optional[str] = Query(None, max_length=64, description="Window end, ISO 8601, exclusive (default: now)"),
    rule_id: Optional[str] = Query(None, min_length=1, max_length=255, description="Only this rule"),
    limit: int = Query(100, ge=1, le=MAX_LIMIT),
    cursor: Optional[str] = Query(None, max_length=1024),
    session: Session = Depends(get_db_session),
) -> RuleOutcomesPage:
    """How each rule's alerts were closed in ION, one item per rule.

    Items are ordered by rule identity (every rule with an id, by id, then
    every rule known only by name), which does not depend on the counts, so
    following ``next_cursor`` with the same window visits each rule once.
    The window is at most 365 days.
    """
    window = _window(since, until)
    policy = NoisyPolicy.from_env()
    records = rule_outcomes(session, window).sorted()
    if rule_id is not None:
        records = [r for r in records if r.key.rule_id == rule_id]
    if cursor is not None:
        after = _decode_cursor(cursor)
        records = [r for r in records if r.key.token > after]

    page = records[:limit]
    more = len(records) > limit
    return RuleOutcomesPage(
        schema_version=SCHEMA,
        window=WindowOut(since=_utc(window.since), until=_utc(window.until)),
        noisy_policy=NoisyPolicyOut(min_closed=policy.min_closed, fp_rate_pct=policy.fp_rate_pct),
        outcome_keys=list(OUTCOMES),
        items=[_item(r, policy) for r in page],
        next_cursor=_encode_cursor(page[-1].key.token) if more else None,
    )

