"""TIDE background sync service.

Periodically pulls key datasets from TIDE (via the existing TideService
SQL queries) and stores them as JSON snapshots in PostgreSQL. The
Detection Engineering page then reads from these snapshots — instant
page loads regardless of TIDE availability or DuckDB lock contention.

The sync runs sequentially (one query at a time) so it never causes
concurrent DuckDB lock pressure. It uses the existing TideService
methods so any query fix applies everywhere automatically.

Public API:
    sync_all(session)              — full refresh of all datasets
    get_snapshot(session, key)     — read a cached snapshot
    get_all_snapshots(session)     — read all cached datasets at once
    start_background_loop(engine)  — launch the periodic background task
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.tide_snapshot import TideSnapshot

logger = logging.getLogger(__name__)

# Which datasets to sync and the TideService method to call for each.
# Each entry is (data_key, method_name, kwargs).
_SYNC_TARGETS = [
    ("posture", "get_posture_stats", {}),
    ("disabled_critical", "get_disabled_critical_high", {}),
    ("gaps", "get_gaps_analysis", {}),
    ("systems", "get_systems", {}),
    ("use_cases", "get_playbooks_with_kill_chains", {}),
]

# Sync interval in seconds (default 5 minutes, configurable via env).
SYNC_INTERVAL = int(os.environ.get("ION_TIDE_SYNC_INTERVAL", "300"))


# ---------------------------------------------------------------------------
# Core sync logic
# ---------------------------------------------------------------------------

def _upsert_snapshot(
    session: Session,
    data_key: str,
    data: object,
    duration_ms: int,
    error: Optional[str] = None,
) -> None:
    """Insert or update a single snapshot row."""
    existing = session.execute(
        select(TideSnapshot).where(TideSnapshot.data_key == data_key)
    ).scalar_one_or_none()

    json_str = json.dumps(data, default=str) if data is not None else "{}"

    if existing:
        existing.data_json = json_str
        existing.fetched_at = datetime.utcnow()
        existing.fetch_duration_ms = duration_ms
        existing.error = error
    else:
        session.add(TideSnapshot(
            data_key=data_key,
            data_json=json_str,
            fetched_at=datetime.utcnow(),
            fetch_duration_ms=duration_ms,
            error=error,
        ))
    session.commit()


def sync_all(session: Session) -> dict:
    """Pull every dataset from TIDE sequentially and store as snapshots.

    Returns a summary dict with per-key status.
    """
    from ion.services.tide_service import get_tide_service, reset_tide_service

    # Force a fresh TideService so config changes are picked up.
    reset_tide_service()
    svc = get_tide_service()

    if not svc.enabled:
        return {"error": "TIDE not configured", "synced": 0}

    results: dict[str, dict] = {}
    synced = 0

    for data_key, method_name, kwargs in _SYNC_TARGETS:
        method = getattr(svc, method_name, None)
        if not method:
            results[data_key] = {"error": f"method {method_name} not found"}
            continue

        t0 = time.time()
        try:
            data = method(**kwargs)
            duration_ms = int((time.time() - t0) * 1000)
            if data is None:
                _upsert_snapshot(session, data_key, None, duration_ms, error="returned None")
                results[data_key] = {"status": "empty", "ms": duration_ms}
            else:
                _upsert_snapshot(session, data_key, data, duration_ms)
                results[data_key] = {"status": "ok", "ms": duration_ms}
                synced += 1
        except Exception as e:
            duration_ms = int((time.time() - t0) * 1000)
            _upsert_snapshot(session, data_key, None, duration_ms, error=type(e).__name__)
            results[data_key] = {"status": "error", "error": type(e).__name__, "ms": duration_ms}
            logger.warning("TIDE sync %s failed: %s", data_key, type(e).__name__)

        # Short pause between queries so TIDE's DuckDB lock can breathe.
        time.sleep(0.3)

    logger.info("TIDE sync complete: %d/%d datasets refreshed", synced, len(_SYNC_TARGETS))
    return {"synced": synced, "total": len(_SYNC_TARGETS), "results": results}


# ---------------------------------------------------------------------------
# Read snapshots
# ---------------------------------------------------------------------------

def get_snapshot(session: Session, data_key: str) -> Optional[dict]:
    """Read a cached snapshot. Returns the parsed JSON dict or None."""
    row = session.execute(
        select(TideSnapshot).where(TideSnapshot.data_key == data_key)
    ).scalar_one_or_none()
    if not row or row.error:
        return None
    try:
        return json.loads(row.data_json)
    except (json.JSONDecodeError, TypeError):
        return None


def get_snapshot_meta(session: Session, data_key: str) -> Optional[dict]:
    """Return metadata (fetched_at, duration, error) without parsing the blob."""
    row = session.execute(
        select(TideSnapshot).where(TideSnapshot.data_key == data_key)
    ).scalar_one_or_none()
    if not row:
        return None
    return {
        "data_key": row.data_key,
        "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None,
        "fetch_duration_ms": row.fetch_duration_ms,
        "error": row.error,
    }


def get_all_snapshots(session: Session) -> dict[str, dict]:
    """Read every snapshot. Returns {data_key: parsed_json}."""
    rows = session.execute(select(TideSnapshot)).scalars().all()
    out: dict[str, dict] = {}
    for row in rows:
        if row.error:
            continue
        try:
            out[row.data_key] = json.loads(row.data_json)
        except (json.JSONDecodeError, TypeError):
            continue
    return out


def get_sync_status(session: Session) -> dict:
    """Return sync health for the dashboard / status API."""
    rows = session.execute(select(TideSnapshot)).scalars().all()
    datasets = {}
    for row in rows:
        datasets[row.data_key] = {
            "fetched_at": row.fetched_at.isoformat() if row.fetched_at else None,
            "fetch_duration_ms": row.fetch_duration_ms,
            "error": row.error,
            "age_seconds": int((datetime.utcnow() - row.fetched_at).total_seconds()) if row.fetched_at else None,
        }
    return {
        "interval_seconds": SYNC_INTERVAL,
        "datasets": datasets,
        "total_datasets": len(_SYNC_TARGETS),
        "healthy": sum(1 for d in datasets.values() if not d.get("error")),
    }


# ---------------------------------------------------------------------------
# Background loop
# ---------------------------------------------------------------------------

async def _background_sync_loop(engine):
    """Run sync_all every SYNC_INTERVAL seconds in a background task."""
    from sqlalchemy.orm import Session as SyncSession, sessionmaker

    SessionLocal = sessionmaker(bind=engine)

    # Initial delay — let the app finish starting up before the first sync.
    await asyncio.sleep(15)

    while True:
        try:
            session = SessionLocal()
            try:
                # Run the sync in a thread to avoid blocking the event loop.
                await asyncio.to_thread(sync_all, session)
            finally:
                session.close()
        except Exception as e:
            logger.error("TIDE background sync error: %s", type(e).__name__)

        await asyncio.sleep(SYNC_INTERVAL)


def start_background_loop(engine) -> asyncio.Task:
    """Launch the background sync task. Call once at app startup."""
    logger.info("TIDE background sync started (interval: %ds)", SYNC_INTERVAL)
    return asyncio.create_task(_background_sync_loop(engine))
