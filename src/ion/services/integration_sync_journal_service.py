"""Durable outbound-sync journal with retry (review 2026-10-08, stage 3).

Review §2 asks for failed sync to sit "beside the affected action". Stage 3's
exit condition asks the alert-to-handover journey to leave "durable records
and **recoverable failures**". Before this, every outbound sync was::

    try:
        service.add_comment(kibana_case_id, comment_text)
    except Exception as e:
        logger.warning("Failed to sync note to Kibana: %s", e)

which satisfies neither: the failure existed only in a log line, nothing
recorded what to retry with, and the case page went on implying the note was
mirrored.

How this behaves, and why:

**One row per logical sync.** Keyed by ``dedupe_key``, so the same sync
repeated during an outage reuses its row rather than piling up thousands of
duplicates. Re-recording refreshes the payload, because the newest intent is
what a retry should send.

**Exponential, capped backoff.** A Kibana restart resolves in seconds; a
misconfigured credential does not resolve at all. Backoff doubles from
``BASE_BACKOFF_SECONDS`` and is capped, so a long outage neither hammers the
endpoint nor schedules a retry a week out.

**``abandoned`` is not ``failed``.** Once the budget is spent ION has stopped
trying and the row says so, with ``next_retry_at`` cleared. A human who has
fixed the integration can :func:`requeue` it. Leaving it at ``failed`` would
present a queue that looks like it is still working.

**A skip is not a success.** When the integration is disabled there is
nothing to sync and nothing failed, so no row is written at all. Recording
success would assert a mirror that does not exist — the same honesty rule as
the dry-run labelling in stage 1.

**The journal never breaks its caller.** It is diagnostics. A journal write
that failed and propagated would turn a Kibana outage into a failed ION
request, which is strictly worse than the fire-and-forget it replaces. Hence
:func:`journalled`, which swallows its own errors.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ion.core.safe_errors import safe_error
from ion.models.integration_sync import SyncAttempt, SyncStatus

logger = logging.getLogger(__name__)


class SyncJournalError(Exception):
    """A journal operation was refused."""


#: Integrations ION mirrors to. Closed on purpose: a typo'd target would
#: produce rows nothing can ever retry, which is a silent queue leak.
VALID_TARGETS = ("kibana", "dfir_iris", "elasticsearch")

#: Operations the journal knows how to describe and, where a handler exists,
#: replay. Also closed, for the same reason.
VALID_OPERATIONS = (
    "case_create",
    "case_update",
    "case_status_push",
    "note_add",
    "alert_status_push",
)

#: Retry budget per logical sync, after which the row is abandoned.
MAX_ATTEMPTS = 6

#: First retry gap. Doubles each failure.
BASE_BACKOFF_SECONDS = 60

#: Ceiling on the gap, so a long outage does not schedule a retry days out.
MAX_BACKOFF_SECONDS = 3600

#: Errors are truncated, not dropped: the first part is the useful part, and
#: an unbounded provider traceback should not bloat every row.
MAX_ERROR_CHARS = 2000

#: Statuses that still need something to happen.
UNRESOLVED_STATUSES = (
    SyncStatus.PENDING.value,
    SyncStatus.FAILED.value,
    SyncStatus.ABANDONED.value,
)

#: ``(target, operation)`` → callable taking the stored payload and returning
#: truthy on success. Populated by :func:`register_retry_handler`, which the
#: sync helpers call at import time. Kept as a plain dict so tests can patch
#: a single entry without a service double.
RETRY_HANDLERS: dict[tuple[str, str], Callable[[dict], Any]] = {}


def register_retry_handler(
    target: str, operation: str, fn: Callable[[dict], Any]
) -> None:
    """Teach the journal how to replay one kind of sync."""
    RETRY_HANDLERS[(target, operation)] = fn


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _naive(value: datetime) -> datetime:
    """Strip the zone for storage; the columns are naive UTC throughout ION."""
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _backoff_seconds(attempt_count: int) -> int:
    """Gap before the next attempt, doubling and capped."""
    gap = BASE_BACKOFF_SECONDS * (2 ** max(0, attempt_count - 1))
    return int(min(gap, MAX_BACKOFF_SECONDS))


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------

def record_attempt(
    session: Session,
    *,
    target: str,
    operation: str,
    entity_type: str,
    entity_id: str,
    dedupe_key: str,
    payload: Optional[dict] = None,
    case_id: Optional[int] = None,
) -> SyncAttempt:
    """Open (or refresh) the journal row for one logical sync.

    Called before the sync is attempted, so a process that dies mid-call
    still leaves evidence that the sync was owed.

    Args:
        session: Database session.
        target: One of :data:`VALID_TARGETS`.
        operation: One of :data:`VALID_OPERATIONS`.
        entity_type: The ION object being mirrored, e.g. ``note``.
        entity_id: Its identifier, as a string.
        dedupe_key: Stable per logical sync, e.g. ``kibana:note_add:77``.
        payload: Everything a retry needs. Must not hold credentials.
        case_id: The case to show the problem against, when there is one.

    Returns:
        The pending :class:`SyncAttempt`.

    Raises:
        SyncJournalError: On an unknown target/operation or a blank key.
    """
    if target not in VALID_TARGETS:
        raise SyncJournalError(
            f"unknown sync target '{target}'; expected one of "
            f"{', '.join(VALID_TARGETS)}"
        )
    if operation not in VALID_OPERATIONS:
        raise SyncJournalError(
            f"unknown sync operation '{operation}'; expected one of "
            f"{', '.join(VALID_OPERATIONS)}"
        )
    if not dedupe_key or not str(dedupe_key).strip():
        raise SyncJournalError("a dedupe_key is required to keep one row per sync")

    key = str(dedupe_key).strip()[:255]
    existing = session.execute(
        select(SyncAttempt).where(SyncAttempt.dedupe_key == key)
    ).scalars().first()

    if existing is not None:
        # The newest intent is what a retry should send.
        existing.payload = payload or {}
        existing.entity_type = entity_type
        existing.entity_id = str(entity_id)
        if case_id is not None:
            existing.case_id = case_id
        if existing.status in (SyncStatus.SUCCEEDED.value, SyncStatus.ABANDONED.value):
            # A fresh request for an already-resolved sync starts over.
            existing.status = SyncStatus.PENDING.value
            existing.attempt_count = 0
            existing.last_error = None
            existing.next_retry_at = None
            existing.resolved_at = None
        session.commit()
        session.refresh(existing)
        return existing

    attempt = SyncAttempt(
        target=target,
        operation=operation,
        entity_type=entity_type,
        entity_id=str(entity_id),
        case_id=case_id,
        status=SyncStatus.PENDING.value,
        payload=payload or {},
        attempt_count=0,
        dedupe_key=key,
    )
    session.add(attempt)
    try:
        session.commit()
    except IntegrityError:
        # Another worker opened the same logical sync first. Theirs is as
        # good as ours, so adopt it rather than failing the caller.
        session.rollback()
        adopted = session.execute(
            select(SyncAttempt).where(SyncAttempt.dedupe_key == key)
        ).scalars().first()
        if adopted is None:
            raise
        return adopted
    session.refresh(attempt)
    return attempt


def _require(session: Session, attempt_id: int) -> SyncAttempt:
    attempt = session.get(SyncAttempt, attempt_id)
    if attempt is None:
        raise SyncJournalError(f"sync attempt {attempt_id} not found")
    return attempt


def mark_succeeded(session: Session, *, attempt_id: int) -> SyncAttempt:
    """The sync went through. Resolve the row and clear the error."""
    attempt = _require(session, attempt_id)
    now = _now()
    attempt.status = SyncStatus.SUCCEEDED.value
    attempt.attempt_count = attempt.attempt_count + 1
    attempt.last_attempt_at = _naive(now)
    attempt.resolved_at = _naive(now)
    attempt.next_retry_at = None
    attempt.last_error = None
    session.commit()
    session.refresh(attempt)
    return attempt


def mark_failed(
    session: Session, *, attempt_id: int, error: str
) -> SyncAttempt:
    """The sync did not go through. Schedule a retry, or give up and say so."""
    attempt = _require(session, attempt_id)
    now = _now()
    attempt.attempt_count = attempt.attempt_count + 1
    attempt.last_attempt_at = _naive(now)
    attempt.last_error = (error or "")[:MAX_ERROR_CHARS] or "unknown error"

    if attempt.attempt_count >= MAX_ATTEMPTS:
        # Budget spent. Say so rather than leaving a retry that will never
        # be honoured.
        attempt.status = SyncStatus.ABANDONED.value
        attempt.next_retry_at = None
        logger.warning(
            "Sync %s (%s %s for %s %s) abandoned after %d attempts: %s",
            attempt.id, attempt.target, attempt.operation,
            attempt.entity_type, attempt.entity_id, attempt.attempt_count,
            attempt.last_error,
        )
    else:
        attempt.status = SyncStatus.FAILED.value
        attempt.next_retry_at = _naive(
            now + timedelta(seconds=_backoff_seconds(attempt.attempt_count))
        )

    session.commit()
    session.refresh(attempt)
    return attempt


def requeue(
    session: Session, *, attempt_id: int, actor_id: Optional[int] = None
) -> SyncAttempt:
    """Put an abandoned (or failed) sync back at the front of the queue.

    For the operator who has just fixed the integration and should not have
    to wait out a backoff. The attempt counter resets, which is the point:
    the previous failures were against a broken configuration.
    """
    attempt = _require(session, attempt_id)
    attempt.status = SyncStatus.PENDING.value
    attempt.attempt_count = 0
    attempt.next_retry_at = None
    attempt.resolved_at = None
    session.commit()
    session.refresh(attempt)
    logger.info(
        "Sync %s requeued by user %s (%s %s)",
        attempt.id, actor_id, attempt.target, attempt.operation,
    )
    return attempt


# ---------------------------------------------------------------------------
# Retry
# ---------------------------------------------------------------------------

def due_for_retry(
    session: Session,
    *,
    now: Optional[datetime] = None,
    limit: int = 50,
) -> list[SyncAttempt]:
    """Syncs that should be attempted now, oldest first.

    Pending rows are due immediately. Failed rows are due once their backoff
    has elapsed. Abandoned and succeeded rows are never due.
    """
    reference = _naive(now or _now())
    rows = session.execute(
        select(SyncAttempt)
        .where(
            SyncAttempt.status.in_(
                (SyncStatus.PENDING.value, SyncStatus.FAILED.value)
            )
        )
        .order_by(SyncAttempt.id.asc())
        .limit(limit * 4)
    ).scalars().all()

    due = []
    for attempt in rows:
        if attempt.status == SyncStatus.PENDING.value:
            due.append(attempt)
        elif attempt.next_retry_at is not None and attempt.next_retry_at <= reference:
            due.append(attempt)
        if len(due) >= limit:
            break
    return due


def retry_attempt(session: Session, *, attempt_id: int) -> dict:
    """Replay one sync through its registered handler.

    A handler that returns falsey is a failure, not a success — a sync
    helper that could not reach the integration returns ``None``, and
    treating that as success is exactly the bug being fixed.

    With no handler registered the row is abandoned rather than retried: a
    sync nothing can perform would otherwise be picked up on every drain
    forever.
    """
    attempt = _require(session, attempt_id)
    handler = RETRY_HANDLERS.get((attempt.target, attempt.operation))

    if handler is None:
        mark_failed(
            session, attempt_id=attempt_id,
            error=(
                f"no retry handler registered for {attempt.target}/"
                f"{attempt.operation}"
            ),
        )
        attempt = _require(session, attempt_id)
        attempt.status = SyncStatus.ABANDONED.value
        attempt.next_retry_at = None
        session.commit()
        return {"attempt_id": attempt_id, "outcome": "abandoned",
                "detail": "no retry handler registered"}

    try:
        result = handler(attempt.payload or {})
    except Exception as exc:  # noqa: BLE001 — the point is to record it
        mark_failed(session, attempt_id=attempt_id,
                    error=safe_error(exc, f"sync_retry[{attempt_id}]"))
        return {"attempt_id": attempt_id, "outcome": "failed",
                "detail": "handler raised"}

    if result:
        mark_succeeded(session, attempt_id=attempt_id)
        return {"attempt_id": attempt_id, "outcome": "succeeded", "detail": ""}

    mark_failed(session, attempt_id=attempt_id,
                error="the integration did not confirm the sync")
    return {"attempt_id": attempt_id, "outcome": "failed",
            "detail": "handler reported no success"}


def drain_retries(
    session: Session,
    *,
    limit: int = 50,
    now: Optional[datetime] = None,
) -> dict:
    """Attempt every due sync and report what happened to each."""
    due = due_for_retry(session, now=now, limit=limit)
    summary = {"attempted": 0, "succeeded": 0, "failed": 0, "abandoned": 0,
               "outcomes": []}

    for attempt in due:
        result = retry_attempt(session, attempt_id=attempt.id)
        summary["attempted"] += 1
        summary[result["outcome"]] = summary.get(result["outcome"], 0) + 1
        summary["outcomes"].append(
            {
                "attempt_id": attempt.id,
                "target": attempt.target,
                "operation": attempt.operation,
                "outcome": result["outcome"],
                "detail": result["detail"],
            }
        )

    if summary["attempted"]:
        logger.info(
            "Sync journal drain: %d attempted, %d succeeded, %d failed, "
            "%d abandoned",
            summary["attempted"], summary["succeeded"], summary["failed"],
            summary["abandoned"],
        )
    return summary


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def case_sync_status(session: Session, case_id: int) -> dict:
    """What the case page shows beside the affected case.

    ``retrying_count`` and ``abandoned_count`` are separate because "still
    trying" and "given up" are different things to the analyst looking at a
    case whose Kibana mirror is behind.
    """
    rows = session.execute(
        select(SyncAttempt)
        .where(
            SyncAttempt.case_id == case_id,
            SyncAttempt.status.in_(UNRESOLVED_STATUSES),
        )
        .order_by(SyncAttempt.id.asc())
    ).scalars().all()

    unresolved = [r.to_dict(max_attempts=MAX_ATTEMPTS) for r in rows]
    abandoned = sum(1 for r in unresolved if r["status"] == SyncStatus.ABANDONED.value)
    retrying = sum(
        1 for r in unresolved
        if r["status"] in (SyncStatus.PENDING.value, SyncStatus.FAILED.value)
    )

    return {
        "case_id": case_id,
        "has_problems": bool(unresolved),
        "unresolved": unresolved,
        "unresolved_count": len(unresolved),
        "retrying_count": retrying,
        "abandoned_count": abandoned,
        "max_attempts": MAX_ATTEMPTS,
    }


def journal_summary(session: Session, limit: int = 50) -> dict:
    """The estate-wide view: how much has drifted, and for how long."""
    by_status: dict[str, int] = {}
    for status, count in session.execute(
        select(SyncAttempt.status, func.count(SyncAttempt.id))
        .group_by(SyncAttempt.status)
    ).all():
        by_status[status] = int(count)

    by_target: dict[str, int] = {}
    for target, count in session.execute(
        select(SyncAttempt.target, func.count(SyncAttempt.id))
        .group_by(SyncAttempt.target)
    ).all():
        by_target[target] = int(count)

    unresolved_rows = session.execute(
        select(SyncAttempt)
        .where(SyncAttempt.status.in_(UNRESOLVED_STATUSES))
        .order_by(SyncAttempt.id.asc())
        .limit(limit)
    ).scalars().all()

    oldest_hours = None
    if unresolved_rows:
        oldest = _aware(unresolved_rows[0].created_at)
        if oldest is not None:
            oldest_hours = round((_now() - oldest).total_seconds() / 3600.0, 2)

    return {
        "as_of": _now().isoformat(),
        "by_status": by_status,
        "by_target": by_target,
        "unresolved_count": sum(
            by_status.get(s, 0) for s in UNRESOLVED_STATUSES
        ),
        "abandoned_count": by_status.get(SyncStatus.ABANDONED.value, 0),
        # None, not 0: zero would read as "something is an hour old".
        "oldest_unresolved_hours": oldest_hours,
        "unresolved": [
            r.to_dict(max_attempts=MAX_ATTEMPTS) for r in unresolved_rows
        ],
        "max_attempts": MAX_ATTEMPTS,
    }


# ---------------------------------------------------------------------------
# The wrapper the sync helpers use
# ---------------------------------------------------------------------------

def journalled(
    session: Optional[Session],
    *,
    target: str,
    operation: str,
    entity_type: str,
    entity_id: Any,
    dedupe_key: str,
    payload: Optional[dict] = None,
    case_id: Optional[int] = None,
):
    """Run a sync with its outcome recorded, without ever raising.

    Used as a context-manager-free helper: pass a zero-argument callable.

    Returns ``(result, journalled_bool)``. A falsey result is recorded as a
    failure, because a sync helper that could not reach the integration
    returns ``None``.

    With no ``session`` the sync still runs — call sites that have no session
    must keep working exactly as before — it simply is not journalled.

    Every journal error is swallowed. The journal is diagnostics; a journal
    write that propagated would turn an integration outage into a failed ION
    request, which is worse than the fire-and-forget it replaces.
    """

    def _run(fn: Callable[[], Any]) -> tuple[Any, bool]:
        if session is None:
            try:
                return fn(), False
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "%s %s failed (not journalled, no session): %s",
                    target, operation, exc,
                )
                return None, False

        attempt = None
        try:
            attempt = record_attempt(
                session,
                target=target,
                operation=operation,
                entity_type=entity_type,
                entity_id=str(entity_id),
                dedupe_key=dedupe_key,
                payload=payload,
                case_id=case_id,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not open a sync journal row: %s", exc)

        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            logger.warning("%s %s failed: %s", target, operation, exc)
            if attempt is not None:
                try:
                    mark_failed(
                        session, attempt_id=attempt.id,
                        error=safe_error(exc, f"{target}/{operation}"),
                    )
                except Exception as journal_exc:  # noqa: BLE001
                    logger.warning("Could not journal the failure: %s", journal_exc)
            return None, attempt is not None

        if attempt is not None:
            try:
                if result:
                    mark_succeeded(session, attempt_id=attempt.id)
                else:
                    mark_failed(
                        session, attempt_id=attempt.id,
                        error="the integration did not confirm the sync",
                    )
            except Exception as journal_exc:  # noqa: BLE001
                logger.warning("Could not journal the outcome: %s", journal_exc)

        return result, attempt is not None

    return _run


__all__ = [
    "SyncJournalError",
    "VALID_TARGETS",
    "VALID_OPERATIONS",
    "MAX_ATTEMPTS",
    "BASE_BACKOFF_SECONDS",
    "MAX_BACKOFF_SECONDS",
    "MAX_ERROR_CHARS",
    "RETRY_HANDLERS",
    "register_retry_handler",
    "record_attempt",
    "mark_succeeded",
    "mark_failed",
    "requeue",
    "due_for_retry",
    "retry_attempt",
    "drain_retries",
    "case_sync_status",
    "journal_summary",
    "journalled",
]
