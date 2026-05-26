"""Periodic retention enforcement for audit-style tables.

Closes Data-Minimisation Audit Gaps G2 (``audit_logs``) and G3
(``security_events``). v0.31.14.

The module is parameterised on a list of retention rules so future
tables (G4 ``ai_chat_*`` retention is the next candidate) can be
added by appending one tuple, not by writing another whole module.

**Default behaviour is no-op.** Both retention env vars are
unset/empty by default — operators have wildly different compliance
windows (90 days here, 7 years there), so ION ships with retention
*opt-in* per deployment to avoid silently deleting logs a customer
audit needs. Setting either env var to a positive integer enables
that table's cleanup.

Environment variables:

* ``ION_DATA_RETENTION_ENABLED`` (default: ``true``) — kill switch
  for the whole loop. Even if individual table retentions are
  configured, setting this to ``false``/``0``/``no``/``off`` stops
  the loop from starting.
* ``ION_DATA_RETENTION_INTERVAL_HOURS`` (default: ``24``) — how
  often the loop wakes. Daily sweep is sufficient for retention
  cleanup; tighter intervals just churn the DB. Floored at 60s.
* ``ION_AUDIT_LOG_RETENTION_DAYS`` (default: unset = disabled).
  When set to a positive integer N, deletes ``audit_logs`` rows
  whose ``timestamp`` is older than N days at sweep time.
* ``ION_SECURITY_EVENTS_RETENTION_DAYS`` (default: unset =
  disabled). When set to a positive integer N, deletes
  ``security_events`` rows whose ``created_at`` is older than N
  days at sweep time.
* ``ION_AI_CHAT_RETENTION_DAYS`` (default: unset = disabled). When
  set to a positive integer N, deletes ``ai_chat_messages`` rows
  whose ``created_at`` is older than N days. Sessions are NOT
  cascaded — only messages.

See ``docs/DATA_MINIMISATION_AUDIT.md`` G2, G3, and G4 for the rationale.
"""

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional, Type

from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

_task: Optional[asyncio.Task] = None
_running = False

_DEFAULT_INTERVAL_HOURS = 24.0
_MIN_INTERVAL_SECONDS = 60


@dataclass(frozen=True)
class RetentionRule:
    """One retention policy: which env var, which model, which timestamp."""

    env_var: str
    model_dotted_path: str  # e.g. "ion.models.user:AuditLog"
    timestamp_column: str   # name of the DateTime column to filter on
    label: str              # human-readable name used in log lines


# Adding a new retention rule? Append a tuple here and document the env var
# in DATA_MINIMISATION_AUDIT.md. The model is loaded lazily inside the loop
# so importing this module is cheap.
RETENTION_RULES: List[RetentionRule] = [
    RetentionRule(
        env_var="ION_AUDIT_LOG_RETENTION_DAYS",
        model_dotted_path="ion.models.user:AuditLog",
        timestamp_column="timestamp",
        label="audit_logs",
    ),
    RetentionRule(
        env_var="ION_SECURITY_EVENTS_RETENTION_DAYS",
        model_dotted_path="ion.models.security:SecurityEvent",
        timestamp_column="created_at",
        label="security_events",
    ),
    # G4 closure (v0.31.15) — AI chat retention. Targets messages (not
    # sessions); CASCADE delete on session removal already handles the
    # session lifecycle. Deleting messages without their session leaves
    # the session row referencing an empty conversation, which is
    # acceptable — the UI handles empty sessions and the user can
    # explicitly delete a session for full cleanup.
    RetentionRule(
        env_var="ION_AI_CHAT_RETENTION_DAYS",
        model_dotted_path="ion.models.ai_chat:AIChatMessage",
        timestamp_column="created_at",
        label="ai_chat_messages",
    ),
]


def _interval_seconds() -> int:
    raw = os.environ.get("ION_DATA_RETENTION_INTERVAL_HOURS", str(_DEFAULT_INTERVAL_HOURS))
    try:
        hours = float(raw)
    except (TypeError, ValueError):
        hours = _DEFAULT_INTERVAL_HOURS
    return max(_MIN_INTERVAL_SECONDS, int(hours * 3600))


def _enabled() -> bool:
    val = os.environ.get("ION_DATA_RETENTION_ENABLED", "true").strip().lower()
    return val not in ("false", "0", "no", "off", "")


def _read_days(env_var: str) -> Optional[int]:
    """Parse a retention env var. Returns days or None if disabled / invalid."""
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return None
    try:
        days = int(raw)
    except ValueError:
        logger.warning(
            "%s is set to %r but is not an integer; treating as disabled",
            env_var, raw,
        )
        return None
    if days <= 0:
        return None
    return days


def _load_model(dotted: str) -> Type:
    """Lazily import ``module:Class`` so this file stays import-light."""
    module_path, _, class_name = dotted.partition(":")
    import importlib
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


def _enforce_one(session, rule: RetentionRule, now: datetime) -> int:
    """Apply one retention rule. Returns rows deleted (0 if rule disabled)."""
    days = _read_days(rule.env_var)
    if days is None:
        return 0
    cutoff = now - timedelta(days=days)
    model = _load_model(rule.model_dotted_path)
    column = getattr(model, rule.timestamp_column)
    # synchronize_session=False is fine — we don't have in-memory references
    # to the rows we're deleting (the loop owns its session).
    deleted = session.query(model).filter(column < cutoff).delete(
        synchronize_session=False,
    )
    session.commit()
    if deleted:
        logger.info(
            "Data retention: deleted %d %s rows older than %d days",
            deleted, rule.label, days,
        )
    return deleted


async def _loop(engine: Engine) -> None:
    """Sleep, then run one pass over every retention rule. Repeat."""
    from ion.storage.database import get_session_factory

    global _running
    interval = _interval_seconds()
    enabled_rules = [
        rule.env_var for rule in RETENTION_RULES if _read_days(rule.env_var) is not None
    ]
    logger.info(
        "Data retention loop started; interval=%ds; enabled retentions=%s",
        interval, enabled_rules or "(none — all rules unset)",
    )

    while _running:
        try:
            await asyncio.sleep(interval)
        except asyncio.CancelledError:
            break
        if not _running:
            break
        try:
            factory = get_session_factory(engine)
            session = factory()
            try:
                now = datetime.utcnow()
                for rule in RETENTION_RULES:
                    try:
                        _enforce_one(session, rule, now)
                    except Exception as e:
                        logger.error(
                            "Retention sweep for %s failed: %s", rule.label, e,
                        )
                        # v0.31.23 (code review): on SQLAlchemy 2.x the
                        # session's autobegin behaviour opens a fresh
                        # implicit transaction after rollback so the
                        # remaining rules in this sweep get clean state.
                        # If ION ever moves back to SA 1.4 legacy mode
                        # (autobegin=False), this rollback-then-reuse
                        # pattern needs an explicit `session.begin()` or
                        # a new session per rule. Tracked in pyproject:
                        # the sqlalchemy pin should be >=2.0.
                        session.rollback()
            finally:
                session.close()
        except Exception as e:
            logger.error("Data retention loop error: %s", e)


def start_background_loop(engine: Engine) -> Optional[asyncio.Task]:
    """Start the periodic data-retention task.

    Idempotent — second call is a no-op. Honours
    ``ION_DATA_RETENTION_ENABLED``.

    Returns the asyncio.Task if started, or None if disabled / already running.
    """
    global _task, _running

    if not _enabled():
        logger.info(
            "Data retention disabled (ION_DATA_RETENTION_ENABLED=false)"
        )
        return None
    if _running:
        return _task

    _running = True
    _task = asyncio.create_task(_loop(engine))
    return _task


def stop_background_loop() -> None:
    """Cancel the loop. Used in tests; not called in production."""
    global _task, _running
    _running = False
    if _task is not None:
        _task.cancel()
        _task = None
