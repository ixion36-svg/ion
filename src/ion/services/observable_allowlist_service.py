"""Applying and managing the observable allowlist.

The matching itself lives in ``services/observable_allowlist`` and has no
database dependency. This module is the part that talks to the table: it
loads the live entries, answers "is this suppressed", counts what each
entry catches, and handles create/update/delete.

Two things worth knowing before changing it.

**The cache is short on purpose.** ``get_or_create`` is on the alert ingest
path, so re-reading the table for every observable would make extraction a
query-per-value. The cache is held for ``_CACHE_TTL_SECONDS`` and dropped
on every write, so a new entry takes effect at once and a stale one cannot
outlive a minute. The counter is written straight through rather than
cached, because a hit count that lags is a hit count nobody trusts.

**Suppression is recorded, not silent.** Every match bumps ``hit_count``
and stores the value, so an entry that has caught nothing in a month and
one that is swallowing thousands of real sightings are both visible in the
list. An allowlist whose effects cannot be seen is a blind spot with
paperwork.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from ion.models.observable_allowlist import ObservableAllowlist
from ion.services.observable_allowlist import (
    AllowlistRule,
    MatchType,
    normalise_pattern,
)

logger = logging.getLogger(__name__)

#: Long enough that extraction does not re-read the table per observable,
#: short enough that an operator adding an entry sees it take effect while
#: they are still looking at the screen.
_CACHE_TTL_SECONDS = 60

_cache: Optional[List[AllowlistRule]] = None
_cache_at: float = 0.0
_cache_lock = threading.Lock()


def invalidate_cache() -> None:
    """Drop the cached rules. Called after every write."""
    global _cache, _cache_at
    with _cache_lock:
        _cache = None
        _cache_at = 0.0


def _live_rules(session: Session) -> List[AllowlistRule]:
    global _cache, _cache_at
    now = time.monotonic()
    with _cache_lock:
        if _cache is not None and (now - _cache_at) < _CACHE_TTL_SECONDS:
            return _cache
    try:
        rows = (
            session.query(ObservableAllowlist)
            .filter(ObservableAllowlist.is_active.is_(True))
            .all()
        )
        rules = [AllowlistRule.from_row(r) for r in rows]
    except Exception as exc:  # noqa: BLE001
        # The allowlist failing must not stop extraction. Erring toward
        # extracting is the right way round: a missing suppression is
        # noise an analyst can see and report, a missing observable is a
        # sighting nobody knows was dropped.
        logger.warning("Observable allowlist unavailable, extracting anyway: %s", exc)
        return []
    with _cache_lock:
        _cache = rules
        _cache_at = now
    return rules


def find_match(
    session: Session, obs_type: Optional[str], value: Optional[str]
) -> Optional[AllowlistRule]:
    """The first live rule suppressing ``value``, or None."""
    for rule in _live_rules(session):
        if rule.matches(obs_type, value):
            return rule
    return None


def is_allowlisted(
    session: Session, obs_type: Optional[str], value: Optional[str]
) -> bool:
    return find_match(session, obs_type, value) is not None


def record_hit(session: Session, rule_id: Optional[int], value: str) -> None:
    """Count a suppression against its entry.

    Written through rather than batched: a hit count that lags is a hit
    count nobody trusts, and this is the only evidence of what the
    allowlist is doing.
    """
    if rule_id is None:
        return
    try:
        (
            session.query(ObservableAllowlist)
            .filter(ObservableAllowlist.id == rule_id)
            .update(
                {
                    ObservableAllowlist.hit_count: ObservableAllowlist.hit_count + 1,
                    ObservableAllowlist.last_hit_at: func.now(),
                    ObservableAllowlist.last_hit_value: str(value)[:512],
                },
                synchronize_session=False,
            )
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not record allowlist hit for %s: %s", rule_id, exc)


def suppressed(
    session: Session, obs_type: Optional[str], value: Optional[str]
) -> Optional[AllowlistRule]:
    """Check and count in one call, for use on the extraction path."""
    rule = find_match(session, obs_type, value)
    if rule is not None:
        record_hit(session, rule.id, str(value))
        logger.debug(
            "Observable suppressed by allowlist %s (%s %s): %s=%s",
            rule.id, rule.match_type, rule.pattern, obs_type, value,
        )
    return rule


# ---------------------------------------------------------------------------
# Management
# ---------------------------------------------------------------------------
class AllowlistError(ValueError):
    """A rejected create or update. The message is shown to the operator."""


def add_entry(
    session: Session,
    *,
    match_type: str,
    pattern: str,
    reason: str,
    observable_type: Optional[str] = None,
    expires_at: Optional[datetime] = None,
    created_by: Optional[str] = None,
    created_by_id: Optional[int] = None,
) -> ObservableAllowlist:
    """Add an entry, or raise ``AllowlistError``.

    A reason is required here and not merely NOT NULL in the table: an
    entry nobody can review is permanent, and the moment it is written is
    the only moment anyone knows why.
    """
    try:
        mt = MatchType(str(match_type).strip().lower())
    except ValueError:
        raise AllowlistError(
            f"Unknown match type {match_type!r}. Use one of: "
            + ", ".join(m.value for m in MatchType)
        ) from None

    if not (reason or "").strip():
        raise AllowlistError(
            "A reason is required. An allowlist entry stops observables "
            "being recorded, and one nobody can review is permanent."
        )

    try:
        canonical = normalise_pattern(mt, pattern)
    except ValueError as exc:
        raise AllowlistError(str(exc)) from None

    scope = (observable_type or "").strip().lower() or None

    existing = (
        session.query(ObservableAllowlist)
        .filter(
            ObservableAllowlist.match_type == mt.value,
            ObservableAllowlist.pattern == canonical,
            ObservableAllowlist.observable_type.is_(None)
            if scope is None
            else ObservableAllowlist.observable_type == scope,
        )
        .first()
    )
    if existing:
        raise AllowlistError(
            f"{canonical} is already allowlisted (entry {existing.id}): "
            f"{existing.reason}"
        )

    entry = ObservableAllowlist(
        match_type=mt.value,
        pattern=canonical,
        observable_type=scope,
        reason=reason.strip(),
        expires_at=expires_at,
        created_by=created_by,
        created_by_id=created_by_id,
        is_active=True,
    )
    session.add(entry)
    session.flush()
    invalidate_cache()
    logger.info(
        "Observable allowlist entry %s added by %s: %s %s (%s)",
        entry.id, created_by or "unknown", mt.value, canonical, reason.strip()[:80],
    )
    return entry


def set_active(session: Session, entry_id: int, active: bool) -> ObservableAllowlist:
    entry = (
        session.query(ObservableAllowlist)
        .filter(ObservableAllowlist.id == entry_id)
        .first()
    )
    if entry is None:
        raise AllowlistError(f"No allowlist entry {entry_id}")
    entry.is_active = bool(active)
    session.flush()
    invalidate_cache()
    return entry


def delete_entry(session: Session, entry_id: int) -> None:
    entry = (
        session.query(ObservableAllowlist)
        .filter(ObservableAllowlist.id == entry_id)
        .first()
    )
    if entry is None:
        raise AllowlistError(f"No allowlist entry {entry_id}")
    session.delete(entry)
    session.flush()
    invalidate_cache()


def list_entries(
    session: Session, include_inactive: bool = True
) -> List[ObservableAllowlist]:
    q = session.query(ObservableAllowlist)
    if not include_inactive:
        q = q.filter(ObservableAllowlist.is_active.is_(True))
    return q.order_by(ObservableAllowlist.id.desc()).all()


def review_summary(session: Session) -> dict:
    """What the list is actually doing, for the page that shows it.

    ``unused`` and ``expired`` are called out because those are the two
    states an allowlist drifts into, and neither announces itself.
    """
    now = datetime.now(timezone.utc)
    entries = list_entries(session)
    expired = [
        e for e in entries
        if e.expires_at
        and (e.expires_at if e.expires_at.tzinfo else e.expires_at.replace(tzinfo=timezone.utc)) <= now
    ]
    return {
        "total": len(entries),
        "active": sum(1 for e in entries if e.is_active),
        "expired": len(expired),
        "never_matched": sum(1 for e in entries if not e.hit_count),
        "total_suppressed": sum(e.hit_count or 0 for e in entries),
    }
