"""Server-Sent Events change-notification channel (v0.39.9).

Replaces per-tab ``setInterval`` polling with one long-lived SSE connection.
The server computes a cheap per-topic *state signature* from the SHARED
database on a fixed cadence and emits a ``refresh`` event ONLY when that
signature changes (*signature* topics), or on every tick (*interval* topics).
The browser reacts by calling its existing JSON-fetch routine
(``loadAlerts`` / ``iqLoad`` / ...), so the data path — and its fine-grained
permission checks — is completely untouched.

Why a DB signature and not an in-process pub/sub bus
----------------------------------------------------
ION runs N uvicorn workers (``docker-compose`` default ``ION_WORKERS=4``).
An ``EventSource`` connection is pinned to one worker; an event published in
another worker's memory would never reach it. The shared Postgres that every
worker already queries IS the cross-worker source of truth, so each worker's
stream loop reads it independently. No ``LISTEN/NOTIFY`` listener, no extra
pooled connection to babysit.

Connection-pool safety
-----------------------
Each signature check opens a **short-lived** session and closes it before
sleeping again — a long-lived SSE connection must never pin a pooled DB
connection for its entire lifetime (one client = one connection forever would
exhaust the pool). The HTTP handler authenticates the same way (see
``events_api.py``).
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Callable, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Env configuration (opt-out + cadence tuning) — ION_* family, like the rest.
# ---------------------------------------------------------------------------

_FALSEY = {"0", "false", "no", "off"}


def _env_int(name: str, default: int) -> int:
    """Positive-int env override; falls back to ``default`` on junk/empty."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        val = int(raw.strip())
    except (TypeError, ValueError):
        return default
    return val if val > 0 else default


def sse_enabled() -> bool:
    """Feature flag. Default ON; ``ION_SSE_ENABLED=false`` forces clients to
    fall back to ``setInterval`` polling (the endpoint then returns 503)."""
    return os.getenv("ION_SSE_ENABLED", "true").strip().lower() not in _FALSEY


# How often a *signature* topic re-checks the DB (seconds). Lower = snappier
# updates, more DB hits. 4s is a good default for a SOC queue.
def _sig_poll_secs() -> int:
    return _env_int("ION_SSE_POLL_INTERVAL", 4)


# Heartbeat comment cadence — keeps reverse proxies (nginx/Cloudflare) from
# culling an idle connection and lets the client tell "quiet" from "dead".
def _heartbeat_secs() -> int:
    return _env_int("ION_SSE_HEARTBEAT", 25)


# After this many consecutive signature failures the stream degrades to
# interval-style refreshes: the page re-fetches on a cadence and surfaces any
# real error through its normal JSON path, instead of sitting silently behind
# healthy-looking keepalives (the client cancels its polling fallback while a
# stream is open, so a quiet-but-broken stream would freeze the view forever).
_SIG_FAILURE_DEGRADE_AFTER = 3


# ---------------------------------------------------------------------------
# Signature functions — cheap, read-only, must tolerate empty tables.
# A signature is any string that changes iff the user-visible state changed.
# ---------------------------------------------------------------------------


def _sig_investigations(session: Session) -> str:
    """Status-count vector + max(id) + max(completed_at) + loop-paused flag.

    Captures every transition an analyst watching the queue cares about:
    a new job (count vector + max-id move), pending->running (vector shifts),
    running->completed/failed (vector + completed_at move), and pause/resume
    of the sweep loop (the system flag). The ``investigations`` table has no
    ``updated_at`` column, hence the status-count vector rather than a single
    MAX(updated_at).
    """
    from ion.models.investigation import Investigation
    from ion.services import system_flags

    rows = session.execute(
        select(Investigation.status, func.count()).group_by(Investigation.status)
    ).all()
    counts = ",".join(f"{status}:{n}" for status, n in sorted(rows, key=lambda r: str(r[0])))
    max_id = session.execute(select(func.max(Investigation.id))).scalar()
    max_done = session.execute(select(func.max(Investigation.completed_at))).scalar()

    try:
        meta = system_flags.get_flag_metadata(
            session, system_flags.INVESTIGATION_LOOP_PAUSED
        )
        paused = system_flags.is_truthy(meta.get("value"))
    except Exception:  # flag table not seeded yet, etc. — non-fatal
        paused = False
        # A failed read deactivates the transaction; roll back so the caller
        # (and any test reusing this session) can keep using it. Harmless in
        # production where _compute_signature opens a fresh session each tick.
        try:
            session.rollback()
        except Exception:
            pass

    return f"{counts}|{max_id}|{max_done}|{int(paused)}"


@dataclass(frozen=True)
class _Topic:
    name: str
    interval: int                                      # server cadence (seconds)
    signature_fn: Optional[Callable[[Session], str]]   # None => interval topic


def _topics() -> dict[str, _Topic]:
    """Built fresh each call so env overrides are honoured without restart of
    the import (cheap — a handful of dataclasses)."""
    return {
        # Pure-Postgres queue → emit only when a job actually changes state.
        "investigations": _Topic("investigations", _sig_poll_secs(), _sig_investigations),
        # ES-backed list (currently a lazy 5-min poll) — preserve cadence,
        # collapse the repeating requests into one connection.
        "alerts": _Topic("alerts", _env_int("ION_SSE_ALERTS_INTERVAL", 300), None),
        # ES/metrics dashboards — values drift continuously, so a fixed cadence
        # over a single connection is the honest replacement for the 30s poll.
        "dashboard": _Topic("dashboard", _env_int("ION_SSE_DASHBOARD_INTERVAL", 30), None),
        "integrations": _Topic("integrations", _env_int("ION_SSE_INTEGRATIONS_INTERVAL", 30), None),
    }


def is_valid_topic(name: str) -> bool:
    return name in _topics()


def _compute_signature(topic: _Topic) -> Optional[str]:
    """Open a short-lived session, compute the signature, close immediately.

    Must NOT use a request-scoped session — that would pin a pooled connection
    for the whole SSE connection lifetime and exhaust the pool.
    """
    if topic.signature_fn is None:
        return None
    from ion.storage.database import get_session_factory

    session = get_session_factory()()
    try:
        return topic.signature_fn(session)
    finally:
        session.close()


def _sse(event: str, data: str) -> bytes:
    """Format one SSE event frame."""
    return f"event: {event}\ndata: {data}\n\n".encode("utf-8")


# Heartbeat is an SSE *comment* line (starts with ':'). Browsers ignore it but
# it keeps the TCP connection and any intermediary proxies alive.
_HEARTBEAT_FRAME = b": keepalive\n\n"


async def event_generator(request, topic_name: str):
    """Async byte-generator backing one SSE connection.

    Emits an immediate ``refresh`` so a fresh OR reconnected client re-syncs,
    then either re-checks the signature every ``tick`` (signature topics) or
    emits on the topic's interval (interval topics), with heartbeats in
    between. Breaks promptly when the client disconnects.
    """
    topic = _topics()[topic_name]
    heartbeat = _heartbeat_secs()

    # retry: bump the browser's reconnect backoff a little above its 3s default
    # so a worker restart doesn't trigger a reconnect storm.
    yield b"retry: 5000\n\n"
    # Prime — re-sync the view on connect/reconnect even if nothing changed.
    yield _sse("refresh", "init")

    last_sig: Optional[str] = None
    if topic.signature_fn is not None:
        try:
            last_sig = await asyncio.to_thread(_compute_signature, topic)
        except Exception:  # DB not ready — first real tick will retry
            last_sig = None

    # Wake at least as often as the heartbeat so idle proxies don't drop us,
    # and never less often than the topic's own cadence.
    tick = max(1, min(topic.interval, heartbeat))
    since_emit = 0.0
    since_beat = 0.0
    sig_failures = 0

    while True:
        await asyncio.sleep(tick)
        if await request.is_disconnected():
            break
        since_emit += tick
        since_beat += tick

        emit = False
        if topic.signature_fn is None:
            # Interval topic — fire on the configured cadence.
            emit = since_emit >= topic.interval
        else:
            # Signature topic — fire only when state actually changed.
            try:
                sig = await asyncio.to_thread(_compute_signature, topic)
            except Exception as exc:
                sig_failures += 1
                # Loud on the first failure and periodically after — a stream
                # that can't see the DB must not fail at debug level only.
                if sig_failures == 1 or sig_failures % 10 == 0:
                    logger.warning(
                        "SSE signature failed for %s (%d consecutive): %s",
                        topic_name, sig_failures, exc,
                    )
                if sig_failures >= _SIG_FAILURE_DEGRADE_AFTER:
                    # Degraded mode: refresh on the topic cadence anyway. The
                    # page's JSON fetch either works (signature-only breakage)
                    # or shows the analyst a real error — never a frozen view.
                    emit = since_emit >= topic.interval
            else:
                if sig_failures:
                    logger.info(
                        "SSE signature for %s recovered after %d failure(s)",
                        topic_name, sig_failures,
                    )
                    sig_failures = 0
                    # State may have moved during the outage — re-sync once.
                    last_sig = sig
                    emit = True
                elif sig != last_sig:
                    last_sig = sig
                    emit = True

        if emit:
            yield _sse("refresh", "change")
            since_emit = 0.0
            since_beat = 0.0
        elif since_beat >= heartbeat:
            yield _HEARTBEAT_FRAME
            since_beat = 0.0
