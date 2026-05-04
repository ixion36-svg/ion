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


def _alert_is_critical(es_service, alert_id: str) -> bool:
    """Best-effort check — fail-open (treat as non-critical) on any error.

    The ES service's alert fetch helpers vary by version; we try the common
    ones and fall back to False. A non-critical false is the safer default
    (no ticker noise) — false negatives surface via manual ticker entries.
    """
    if es_service is None:
        return False
    try:
        fetch = getattr(es_service, "get_alert_by_id", None) or getattr(
            es_service, "fetch_alert", None
        )
        if fetch is None:
            return False
        alert = fetch(alert_id)
    except Exception:
        return False
    if not alert:
        return False

    # Try the common severity shapes used by ION's ES wrapper.
    severity = (
        alert.get("severity")
        or (alert.get("rule") or {}).get("severity")
        or alert.get("kibana.alert.severity")
    )
    if not severity and isinstance(alert.get("raw_data"), dict):
        raw = alert["raw_data"]
        severity = (
            raw.get("severity")
            or (raw.get("rule") or {}).get("severity")
            or raw.get("kibana.alert.severity")
        )
    return str(severity or "").lower() == "critical"


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
    stuck = (
        session.query(AlertTriage)
        .filter(
            AlertTriage.status == AlertTriageStatus.OPEN,
            AlertTriage.case_id.is_(None),
            AlertTriage.created_at < cutoff,
        )
        .all()
    )

    created = 0
    for triage in stuck:
        if not _alert_is_critical(es_service, triage.es_alert_id):
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
            # Already tracked — leave as-is (and make sure it isn't resolved).
            if existing.resolved_at is not None:
                existing.resolved_at = None
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
        if triage.case_id is not None or triage.status != AlertTriageStatus.OPEN:
            ticker.resolved_at = datetime.now(timezone.utc)
            resolved += 1

    session.commit()
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
