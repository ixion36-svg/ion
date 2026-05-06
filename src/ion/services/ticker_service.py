"""Ticker background producer — flags critical alerts without a case.

Runs on advisory lock ``LOCK_TICKER_BG`` (1018) so only one worker produces.
On each tick it:

1. Finds OPEN AlertTriage rows with ``case_id IS NULL`` older than a
   configurable threshold.
2. For each, checks whether the underlying ES alert is critical severity.
3. Creates a ``Ticker(kind=critical_alert, severity=critical)`` scoped to
   that es_alert_id (the uniqueness constraint makes it idempotent).
4. Resolves any existing critical_alert ticker whose underlying alert has
   since been cased.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ion.core.config import get_config
from ion.models.alert_triage import AlertTriage, AlertTriageStatus
from ion.models.ticker import (
    Ticker,
    TickerKind,
    TickerSeverity,
    TickerSourceType,
)
from ion.storage.database import (
    get_engine,
    get_session_factory,
    run_locked,
)

logger = logging.getLogger(__name__)


_stop_event = threading.Event()
_loop_thread: Optional[threading.Thread] = None
_last_run_lock = threading.Lock()
_last_run_at: Optional[datetime] = None
_last_result: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Core tick
# ---------------------------------------------------------------------------


def _critical_alert_ids_batch(es_service, alert_ids: list) -> set:
    """Return the subset of ``alert_ids`` that ES says are critical.

    v0.19.6: was a per-row ``_alert_is_critical`` that fetched each
    triage's ES doc one-by-one via ``get_alert_by_id`` — except that
    method has never existed on ``ElasticsearchService`` (the wrapper
    exposes ``get_alerts_by_ids`` and ``get_alerts``, and that
    contract drift made the ticker emit zero rows on every deploy).
    Now: one batched ``get_alerts_by_ids`` call per tick. The wrapper
    is async, so we hop into a fresh event loop with ``asyncio.run``
    — fine because the ticker tick is itself called from a worker
    thread, not from inside an existing loop.
    """
    if es_service is None or not alert_ids:
        return set()
    fetch = getattr(es_service, "get_alerts_by_ids", None)
    if fetch is None:
        logger.warning(
            "Ticker: ES service has no get_alerts_by_ids method — no critical tickers will fire"
        )
        return set()
    try:
        import asyncio
        alerts = asyncio.run(fetch(list(alert_ids)))
    except Exception as exc:
        logger.warning("Ticker: batched ES fetch failed: %s", exc)
        return set()

    critical: set = set()
    for alert in alerts or []:
        # ElasticsearchAlert dataclass has a flat ``severity`` field
        # parsed from whichever raw shape the producer used. Belt-and-
        # braces: also walk raw_data in case the parser missed it.
        sev = getattr(alert, "severity", None)
        if not sev:
            raw = getattr(alert, "raw_data", None) or {}
            if isinstance(raw, dict):
                sev = (
                    raw.get("severity")
                    or (raw.get("rule") or {}).get("severity")
                    or raw.get("kibana.alert.severity")
                    or raw.get("event", {}).get("severity")
                )
        if str(sev or "").lower() == "critical":
            aid = getattr(alert, "id", None)
            if aid:
                critical.add(aid)
    return critical


def run_ticker_once(session: Session) -> Dict[str, Any]:
    """One pass — create missing critical tickers and resolve fixed ones."""
    try:
        threshold_min = int(
            os.environ.get("ION_TICKER_CRITICAL_NO_CASE_MIN", "10")
        )
    except ValueError:
        threshold_min = 10
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=threshold_min)

    try:
        from ion.services.elasticsearch_service import ElasticsearchService
        es_service = ElasticsearchService()
    except Exception:
        es_service = None

    # ------------- Create / refresh critical-alert tickers -----------------
    # v0.19.3: was status == OPEN, but in practice nearly every triage-row
    # creator (kibana_sync, case_grouper, bulk_ack, create_case) sets the
    # row to ACKNOWLEDGED on insertion — only the SQLAlchemy default leaves
    # it OPEN, and almost no path relies on that default. The producer was
    # therefore filtering for a state that's vanishingly rare in real data,
    # silently producing zero tickers regardless of how many critical
    # uncased alerts existed. Filter for "anything that isn't closed" so
    # the ticker fires for the actual queue the analyst sees.
    stuck = (
        session.query(AlertTriage)
        .filter(
            AlertTriage.status != AlertTriageStatus.CLOSED,
            AlertTriage.case_id.is_(None),
            AlertTriage.created_at < cutoff,
        )
        .all()
    )
    logger.info(
        "Ticker tick: %d uncased non-closed triage rows older than %dm",
        len(stuck), threshold_min,
    )

    # v0.19.6: classify all stuck rows in one batched ES call, not one
    # call per row (which also relied on a method that doesn't exist).
    critical_ids = _critical_alert_ids_batch(
        es_service, [t.es_alert_id for t in stuck]
    )
    logger.info("Ticker tick: %d of %d are critical", len(critical_ids), len(stuck))

    created = 0
    for triage in stuck:
        if triage.es_alert_id not in critical_ids:
            continue
        existing = (
            session.query(Ticker)
            .filter(
                Ticker.kind == TickerKind.CRITICAL_ALERT,
                Ticker.source_ref == triage.es_alert_id,
            )
            .one_or_none()
        )
        if existing is not None:
            # v0.19.13: was un-resolving any matching ticker on every
            # tick, which made manual /api/ticker/{id}/resolve and the
            # bulk "Resolve all critical-alert" button futile — operators
            # would clear the strip, the producer would re-flip them
            # active 60s later. Leave whatever state the operator (or
            # the auto-resolver) put the ticker in. New genuinely-new
            # alerts produce new ticker rows; this branch only runs for
            # an existing source_ref match.
            continue
        ticker = Ticker(
            kind=TickerKind.CRITICAL_ALERT,
            severity=TickerSeverity.CRITICAL,
            title=f"Critical alert with no case (>{threshold_min}m)",
            body=(
                f"Alert `{triage.es_alert_id}` has been OPEN for over "
                f"{threshold_min} minutes without being assigned to a case."
            ),
            link_url=f"/alerts/{triage.es_alert_id}",
            source_type=TickerSourceType.AUTO,
            source_ref=triage.es_alert_id,
        )
        session.add(ticker)
        try:
            session.flush()
            created += 1
        except IntegrityError:
            # Race with another worker — the uniqueness constraint caught it.
            session.rollback()

    # ------------- Resolve tickers whose alert is now cased ----------------
    active_critical = (
        session.query(Ticker)
        .filter(
            Ticker.kind == TickerKind.CRITICAL_ALERT,
            Ticker.resolved_at.is_(None),
        )
        .all()
    )

    resolved = 0
    for ticker in active_critical:
        if not ticker.source_ref:
            continue
        triage = (
            session.query(AlertTriage)
            .filter(AlertTriage.es_alert_id == ticker.source_ref)
            .one_or_none()
        )
        if triage is None:
            continue
        # v0.19.3: mirror the create-side filter — resolve when the alert
        # is cased OR closed. Was checking != OPEN, which prematurely
        # resolved tickers the moment a user clicked "acknowledge".
        if triage.case_id is not None or triage.status == AlertTriageStatus.CLOSED:
            ticker.resolved_at = datetime.now(timezone.utc)
            resolved += 1

    session.commit()
    logger.info(
        "Ticker tick result: created=%d resolved=%d active_after=%d",
        created, resolved, len(active_critical) - resolved,
    )
    return {"created": created, "resolved": resolved}


def _tick() -> Dict[str, Any]:
    factory = get_session_factory()
    session = factory()
    try:
        summary = run_ticker_once(session)
    except Exception as exc:
        logger.exception("Ticker tick crashed: %s", exc)
        summary = {"created": 0, "resolved": 0, "error": str(exc)}
    finally:
        session.close()
    with _last_run_lock:
        global _last_run_at, _last_result
        _last_run_at = datetime.now(timezone.utc)
        _last_result = summary
    return summary


# ---------------------------------------------------------------------------
# Loop management
# ---------------------------------------------------------------------------


def run_ticker_loop(interval_s: int = 60) -> None:
    """Spawn the background thread. Idempotent per-process."""
    global _loop_thread
    if _loop_thread is not None and _loop_thread.is_alive():
        logger.info("Ticker loop already running — skipping")
        return

    def _loop() -> None:
        logger.info("Ticker background loop started (interval: %ds)", interval_s)
        while not _stop_event.is_set():
            try:
                _tick()
            except Exception as exc:
                logger.warning("Ticker loop error: %s", exc)
            _stop_event.wait(interval_s)
        logger.info("Ticker loop stopped")

    _loop_thread = threading.Thread(
        target=_loop, daemon=True, name="ion-ticker"
    )
    _loop_thread.start()


def stop_ticker_loop() -> None:
    _stop_event.set()


def start_ticker_if_enabled(engine=None) -> bool:
    enabled_env = os.environ.get("ION_TICKER_ENABLED", "").lower()
    if enabled_env in ("false", "0", "no"):
        logger.info("Ticker disabled by ION_TICKER_ENABLED=%s", enabled_env)
        return False

    try:
        interval_s = int(os.environ.get("ION_TICKER_INTERVAL_S", "60"))
    except ValueError:
        interval_s = 60

    if engine is None:
        engine = get_engine(get_config().db_path)

    try:
        from ion.storage.database import LOCK_TICKER_BG  # type: ignore
        lock_id = LOCK_TICKER_BG
    except ImportError:
        lock_id = 1018

    def _start() -> None:
        run_ticker_loop(interval_s=interval_s)

    return run_locked(
        engine, lock_id, "ticker_bg_loop", _start, hold_until_close=True
    )


def get_last_run_info():
    with _last_run_lock:
        return _last_run_at, (dict(_last_result) if _last_result else None)
