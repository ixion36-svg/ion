"""TI-report cache sync + chunk-embedding background producer (v0.53.0).

Runs under advisory lock ``LOCK_TI_REPORT_BG`` (1028). Each tick does two
phases in sequence — one leader, one lock, because embedding depends on a
fresh cache:

1. **Sync**: fetch the most recent OpenCTI reports (one GraphQL list query,
   bodies included) and upsert them into the local ``ti_reports`` cache
   keyed on the OpenCTI id. Bodies are clipped to
   ``MAX_REPORT_BODY_CHARS``. OpenCTI being unconfigured or unreachable
   skips the phase silently — previously cached reports keep serving
   retrieval (the offline/air-gap point of having a cache at all).
2. **Embed**: chunk + embed new and stale cached reports into
   ``ti_report_chunk_embeddings`` — same discipline as the KB loop
   (v0.51.0): whole-report staleness hash with a chunk-scheme marker,
   atomic per-report replace (no partial chunk sets), batch budget counts
   chunk embeds with an at-least-one-report guarantee, back-off after 3
   consecutive embed failures.

Gate ``ION_TI_REPORT_RAG_ENABLED`` — default ON (v0.36.0 philosophy):
without OpenCTI the sync no-ops, without Ollama the embed no-ops, and the
retrieval layer returns nothing. Interval ``ION_TI_REPORT_SYNC_INTERVAL_S``
(default 1800s — intel moves slower than alerts); sync page size
``ION_TI_REPORT_SYNC_LIMIT`` (default 100); embed batch
``ION_TI_EMBEDDING_BATCH`` (default 40 chunks).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.core import apm
from ion.core.config import get_config
from ion.models.ti_report import (
    MAX_REPORT_BODY_CHARS,
    TIReport,
    TIReportChunkEmbedding,
)
from ion.services.embedding_service import (
    DEFAULT_MODEL,
    chunk_body,
    get_embedding_service,
)
from ion.storage.database import get_engine, get_session_factory, run_locked

logger = logging.getLogger(__name__)


_stop_event = threading.Event()
_loop_thread: Optional[threading.Thread] = None
_last_run_lock = threading.Lock()
_last_run_at: Optional[datetime] = None
_last_result: Optional[Dict[str, Any]] = None

# Chunking parameters — mirrors the KB corpus. _CHUNK_SCHEME is
# folded into the staleness hash; bump it (t2, …) if these change so the
# corpus re-chunks exactly once.
_CHUNK_TARGET_CHARS = 1600
_CHUNK_OVERLAP_CHARS = 200
_MAX_CHUNKS_PER_REPORT = 32
_CHUNK_SCHEME = "t1"


def ti_report_rag_enabled() -> bool:
    return os.environ.get("ION_TI_REPORT_RAG_ENABLED", "true").lower() in (
        "true", "1", "yes",
    )


# ---------------------------------------------------------------------------
# Phase 1 — sync the local cache from OpenCTI
# ---------------------------------------------------------------------------


def run_ti_report_sync_once(session: Session) -> Dict[str, Any]:
    """Fetch recent reports and upsert the local cache. Best-effort."""
    try:
        from ion.services.opencti_service import get_opencti_service
        svc = get_opencti_service()
        if not svc.is_configured:
            return {"synced": 0, "opencti_unconfigured": True}
    except Exception as exc:  # noqa: BLE001
        logger.debug("TI-report sync: OpenCTI service unavailable: %s", exc)
        return {"synced": 0, "opencti_unconfigured": True}

    try:
        limit = int(os.environ.get("ION_TI_REPORT_SYNC_LIMIT", "100"))
    except ValueError:
        limit = 100

    try:
        reports = asyncio.run(svc.fetch_recent_reports(limit=limit))
    except Exception as exc:  # noqa: BLE001 — network best-effort
        logger.debug("TI-report sync: fetch failed: %s", exc)
        return {"synced": 0, "fetch_failed": True}

    now = datetime.now(timezone.utc)
    created = updated = unchanged = 0
    for rep in reports:
        body = (rep.get("body") or "")[:MAX_REPORT_BODY_CHARS]
        row = session.execute(
            select(TIReport).where(TIReport.opencti_id == rep["opencti_id"])
        ).scalar_one_or_none()
        if row is None:
            session.add(TIReport(
                opencti_id=rep["opencti_id"],
                name=str(rep["name"])[:500],
                published=(str(rep["published"])[:64] if rep.get("published") else None),
                report_types=rep.get("report_types") or [],
                confidence=rep.get("confidence"),
                source=(str(rep["source"])[:255] if rep.get("source") else None),
                labels=rep.get("labels") or [],
                content=body,
                fetched_at=now,
            ))
            created += 1
        elif (
            row.name != str(rep["name"])[:500]
            or (row.content or "") != body
            or (row.labels or []) != (rep.get("labels") or [])
        ):
            row.name = str(rep["name"])[:500]
            row.published = str(rep["published"])[:64] if rep.get("published") else None
            row.report_types = rep.get("report_types") or []
            row.confidence = rep.get("confidence")
            row.source = str(rep["source"])[:255] if rep.get("source") else None
            row.labels = rep.get("labels") or []
            row.content = body
            row.fetched_at = now
            updated += 1
        else:
            unchanged += 1
    session.commit()
    return {"synced": created + updated, "created": created,
            "updated": updated, "unchanged": unchanged}


# ---------------------------------------------------------------------------
# Phase 2 — chunk + embed new/stale cached reports
# ---------------------------------------------------------------------------


def _report_source_text(report: TIReport, chunk: str) -> str:
    """The text embedded for one chunk — title + labels anchor every chunk."""
    parts = [f"Report: {report.name}"]
    if report.labels:
        parts.append("Labels: " + ", ".join(str(x) for x in report.labels[:10]))
    if chunk:
        parts.append(f"Content: {chunk}")
    return "\n".join(parts)


def _report_hash_input(report: TIReport) -> str:
    return (
        f"{_CHUNK_SCHEME}\nReport: {report.name}\n"
        f"Labels: {report.labels or []}\nContent: {report.content or ''}"
    )


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def run_ti_report_embedding_once(session: Session) -> Dict[str, Any]:
    """One embed pass — same shape as the KB chunk loop (v0.51.0)."""
    try:
        batch_limit = int(os.environ.get("ION_TI_EMBEDDING_BATCH", "40"))
    except ValueError:
        batch_limit = 40

    svc = get_embedding_service()
    if not svc.is_enabled:
        return {"scanned": 0, "embedded": 0, "disabled": True}

    reports = (
        session.execute(
            select(TIReport)
            .order_by(TIReport.id.desc())
            .limit(max(batch_limit, 20) * 4)
        ).scalars().all()
    )

    existing: Dict[int, TIReportChunkEmbedding] = {}
    report_ids = [r.id for r in reports]
    if report_ids:
        for row in session.execute(
            select(TIReportChunkEmbedding).where(
                TIReportChunkEmbedding.report_id.in_(report_ids),
                TIReportChunkEmbedding.chunk_index == 0,
            )
        ).scalars().all():
            existing[row.report_id] = row

    reports_embedded = chunks_embedded = skipped = failed = scanned = 0
    for report in reports:
        if chunks_embedded >= batch_limit:
            break
        scanned += 1
        hsh = _hash(_report_hash_input(report))
        row = existing.get(report.id)
        if (
            row is not None
            and row.source_text_hash == hsh
            and row.model_name == svc.model_tag
        ):
            skipped += 1
            continue

        chunks = chunk_body(
            report.content or "",
            target_chars=_CHUNK_TARGET_CHARS,
            overlap_chars=_CHUNK_OVERLAP_CHARS,
            max_chunks=_MAX_CHUNKS_PER_REPORT,
        )
        if not chunks:
            continue

        vectors: Optional[list] = []
        for chunk in chunks:
            vec = svc.embed(_report_source_text(report, chunk), mode="document")
            if vec is None:
                vectors = None
                break
            vectors.append(vec)
        if vectors is None:
            failed += 1
            if failed >= 3:
                break
            continue

        now = datetime.now(timezone.utc)
        session.query(TIReportChunkEmbedding).filter(
            TIReportChunkEmbedding.report_id == report.id
        ).delete(synchronize_session="fetch")
        for idx, (chunk, vec) in enumerate(zip(chunks, vectors)):
            session.add(TIReportChunkEmbedding(
                report_id=report.id,
                chunk_index=idx,
                chunk_text=chunk,
                embedding=vec,
                model_name=svc.model_tag,
                embedded_at=now,
                source_text_hash=hsh,
            ))
        reports_embedded += 1
        chunks_embedded += len(chunks)

    session.commit()
    return {
        "scanned": scanned,
        "embedded": reports_embedded,
        "chunks": chunks_embedded,
        "skipped_fresh": skipped,
        "failed": failed,
        "model": svc.model,
    }


# ---------------------------------------------------------------------------
# Loop management
# ---------------------------------------------------------------------------


def _tick() -> Dict[str, Any]:
    factory = get_session_factory()
    session = factory()
    try:
        with apm.background_transaction("ti_report_loop"):
            sync = run_ti_report_sync_once(session)
            embed = run_ti_report_embedding_once(session)
            summary = {"sync": sync, "embed": embed}
    except Exception as exc:
        logger.exception("TI-report tick crashed: %s", exc)
        summary = {"error": str(exc)}
    finally:
        session.close()
    with _last_run_lock:
        global _last_run_at, _last_result
        _last_run_at = datetime.now(timezone.utc)
        _last_result = summary
    return summary


def run_ti_report_loop(interval_s: int = 1800) -> None:
    global _loop_thread
    if _loop_thread is not None and _loop_thread.is_alive():
        logger.info("TI-report loop already running — skipping")
        return

    def _loop() -> None:
        logger.info(
            "TI-report background loop started (interval: %ds, model: %s)",
            interval_s,
            os.environ.get("ION_EMBEDDING_MODEL", DEFAULT_MODEL),
        )
        while not _stop_event.is_set():
            try:
                _tick()
            except Exception as exc:
                logger.warning("TI-report loop error: %s", exc)
            _stop_event.wait(interval_s)
        logger.info("TI-report loop stopped")

    _loop_thread = threading.Thread(
        target=_loop, daemon=True, name="ion-ti-report"
    )
    _loop_thread.start()


def stop_ti_report_loop() -> None:
    _stop_event.set()


def start_ti_report_if_enabled(engine=None) -> bool:
    """Gated by ION_TI_REPORT_RAG_ENABLED — default ON. Both phases degrade
    to no-ops without their integration (OpenCTI for sync, Ollama for
    embedding), so default-on costs an idle estate nothing."""
    enabled_env = os.environ.get("ION_TI_REPORT_RAG_ENABLED", "true").lower()
    if enabled_env not in ("true", "1", "yes"):
        logger.info(
            "TI-report RAG disabled (set ION_TI_REPORT_RAG_ENABLED=false to opt out)"
        )
        return False

    try:
        interval_s = int(os.environ.get("ION_TI_REPORT_SYNC_INTERVAL_S", "1800"))
    except ValueError:
        interval_s = 1800

    if engine is None:
        engine = get_engine(get_config().db_path)

    try:
        from ion.storage.database import LOCK_TI_REPORT_BG  # type: ignore
        lock_id = LOCK_TI_REPORT_BG
    except ImportError:
        lock_id = 1028

    def _start() -> None:
        run_ti_report_loop(interval_s=interval_s)

    return run_locked(
        engine, lock_id, "ti_report_bg_loop", _start, hold_until_close=True
    )


def get_last_run_info():
    with _last_run_lock:
        return _last_run_at, (dict(_last_result) if _last_result else None)
