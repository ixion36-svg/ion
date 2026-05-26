"""Periodic cleanup of expired user_sessions rows.

Closes Data-Minimisation Audit Gap G1 (v0.31.13). The
``AuthService.cleanup_expired_sessions()`` helper has existed since
the auth service was introduced, but it had no scheduled caller —
so expired sessions for dormant users (departed staff, abandoned
accounts) accumulated indefinitely, each row carrying ``ip_address``
+ ``user_agent`` PII. This module wires the helper into ION's
existing background-loop pattern (advisory lock + ``asyncio.create_task``)
so cleanup runs on a sane cadence without any operator action.

The complementary per-user cleanup that happens at login time
(``delete_expired_for_user``, ``auth/service.py:140``) is unchanged
and remains the primary mechanism for active users. This loop only
catches the tail: sessions whose user never logs back in.

Environment variables:

* ``ION_SESSION_CLEANUP_ENABLED`` (default: ``true``) — set to
  ``false``/``0``/``no``/``off`` to disable the loop entirely. The
  module still imports cleanly so feature flags can flip at runtime
  on the next restart.
* ``ION_SESSION_CLEANUP_INTERVAL_HOURS`` (default: ``6``) — how often
  the loop wakes to sweep expired rows. Floored to 60s in case of
  misconfiguration so the loop can't busy-spin.

See ``docs/DATA_MINIMISATION_AUDIT.md`` G1 for the rationale.
"""

import asyncio
import logging
import os
from typing import Optional

from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

_task: Optional[asyncio.Task] = None
_running = False

_DEFAULT_INTERVAL_HOURS = 6.0
_MIN_INTERVAL_SECONDS = 60


def _interval_seconds() -> int:
    raw = os.environ.get("ION_SESSION_CLEANUP_INTERVAL_HOURS", str(_DEFAULT_INTERVAL_HOURS))
    try:
        hours = float(raw)
    except (TypeError, ValueError):
        hours = _DEFAULT_INTERVAL_HOURS
    return max(_MIN_INTERVAL_SECONDS, int(hours * 3600))


def _enabled() -> bool:
    val = os.environ.get("ION_SESSION_CLEANUP_ENABLED", "true").strip().lower()
    return val not in ("false", "0", "no", "off", "")


async def _loop(engine: Engine) -> None:
    """Sleep, then run one cleanup pass. Repeat until _running flips false."""
    from ion.auth.service import AuthService
    from ion.storage.database import get_session_factory

    global _running
    interval = _interval_seconds()
    logger.info("Session cleanup loop started; interval=%ds", interval)

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
                deleted = AuthService(session).cleanup_expired_sessions()
                if deleted:
                    logger.info("Session cleanup: deleted %d expired sessions", deleted)
            finally:
                session.close()
        except Exception as e:
            logger.error("Session cleanup pass failed: %s", e)


def start_background_loop(engine: Engine) -> Optional[asyncio.Task]:
    """Start the periodic session-cleanup task.

    Idempotent — second call is a no-op. Honours
    ``ION_SESSION_CLEANUP_ENABLED``.

    Returns the asyncio.Task if started, or None if disabled / already running.
    """
    global _task, _running

    if not _enabled():
        logger.info(
            "Session cleanup disabled (ION_SESSION_CLEANUP_ENABLED=false)"
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
