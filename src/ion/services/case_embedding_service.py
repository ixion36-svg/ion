"""Case-embedding background producer.

Runs under advisory lock ``LOCK_CASE_EMBEDDING_BG`` (1019). On each tick:

1. Build the embed-source text for each case (title + description +
   triggered rules + affected hosts + evidence summary + Bob's latest
   investigation summary).
2. Hash the source text (SHA-256).
3. Find cases whose ``case_embeddings`` row is missing OR whose
   ``source_text_hash`` differs from the current hash (stale — case edited).
4. Embed the stale/missing ones via ``EmbeddingService``.
5. Upsert the ``CaseEmbedding`` row.

Honours ``ION_EMBEDDING_ENABLED`` and ``ION_CASE_EMBEDDING_INTERVAL_S``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.core.config import get_config
from ion.models.alert_triage import AlertCase
from ion.models.case_embedding import CaseEmbedding
from ion.models.investigation import Investigation
from ion.services.embedding_service import (
    DEFAULT_MODEL,
    get_embedding_service,
)
from ion.storage.database import get_engine, get_session_factory, run_locked

logger = logging.getLogger(__name__)


_stop_event = threading.Event()
_loop_thread: Optional[threading.Thread] = None
_last_run_lock = threading.Lock()
_last_run_at: Optional[datetime] = None
_last_result: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Source-text construction
# ---------------------------------------------------------------------------


def _case_source_text(session: Session, case: AlertCase) -> str:
    """Build the blob of text that represents this case for embedding.

    Designed to be stable — same case, same text. If the case is edited
    (title, description, notes) or a new investigation summary lands, the
    hash will change and the background loop re-embeds.
    """
    parts: list[str] = []
    if case.title:
        parts.append(f"Title: {case.title}")
    if case.description:
        parts.append(f"Description: {case.description}")
    if case.affected_hosts:
        parts.append("Hosts: " + ", ".join(str(h) for h in case.affected_hosts))
    if case.affected_users:
        parts.append("Users: " + ", ".join(str(u) for u in case.affected_users))
    if case.triggered_rules:
        parts.append("Rules: " + ", ".join(str(r) for r in case.triggered_rules))
    if case.evidence_summary:
        parts.append(f"Evidence: {case.evidence_summary}")

    # Bob's most recent investigation summary for any alert in this case
    # adds strong signal — two cases with similar Bob-analyses are likely
    # similar in substance even when titles differ.
    if case.source_alert_ids:
        last_inv = (
            session.execute(
                select(Investigation)
                .where(Investigation.alert_id_ref.in_(list(case.source_alert_ids)))
                .where(Investigation.summary_text.isnot(None))
                .order_by(Investigation.id.desc())
                .limit(1)
            ).scalar_one_or_none()
        )
        if last_inv and last_inv.summary_text:
            parts.append(f"AI summary: {last_inv.summary_text}")
    return "\n".join(parts)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# Core tick
# ---------------------------------------------------------------------------


def run_case_embedding_once(session: Session) -> Dict[str, Any]:
    """One pass — embed new + stale cases.

    Batched at 50 per tick to keep Ollama responsive for interactive AI
    chat. Remaining cases picked up on the next tick.
    """
    try:
        batch_limit = int(os.environ.get("ION_CASE_EMBEDDING_BATCH", "50"))
    except ValueError:
        batch_limit = 50

    svc = get_embedding_service()
    if not svc.is_enabled:
        return {"scanned": 0, "embedded": 0, "disabled": True}

    cases = (
        session.execute(
            select(AlertCase)
            .order_by(AlertCase.id.desc())
            .limit(batch_limit * 4)
        ).scalars().all()
    )

    # Pre-load existing embeddings for this batch for a cheap dedup check.
    case_ids = [c.id for c in cases]
    existing = {}
    if case_ids:
        existing = {
            row.case_id: row
            for row in session.execute(
                select(CaseEmbedding).where(CaseEmbedding.case_id.in_(case_ids))
            ).scalars().all()
        }

    embedded = 0
    skipped = 0
    failed = 0
    scanned = 0

    for case in cases:
        if embedded >= batch_limit:
            break
        scanned += 1
        source = _case_source_text(session, case)
        if not source:
            continue
        hsh = _hash(source)
        row = existing.get(case.id)
        if row is not None and row.source_text_hash == hsh and row.model_name == svc.model:
            skipped += 1
            continue

        vec = svc.embed(source)
        if vec is None:
            failed += 1
            # Ollama unreachable or model missing — back off for this tick,
            # try again next interval. Avoid hammering.
            if failed >= 3:
                break
            continue

        now = datetime.now(timezone.utc)
        if row is None:
            session.add(
                CaseEmbedding(
                    case_id=case.id,
                    embedding=vec,
                    model_name=svc.model,
                    embedded_at=now,
                    source_text_hash=hsh,
                )
            )
        else:
            row.embedding = vec
            row.model_name = svc.model
            row.embedded_at = now
            row.source_text_hash = hsh
        embedded += 1

    session.commit()
    return {
        "scanned": scanned,
        "embedded": embedded,
        "skipped_fresh": skipped,
        "failed": failed,
        "model": svc.model if svc.is_enabled else None,
    }


def _tick() -> Dict[str, Any]:
    factory = get_session_factory()
    session = factory()
    try:
        summary = run_case_embedding_once(session)
    except Exception as exc:
        logger.exception("Case embedding tick crashed: %s", exc)
        summary = {"scanned": 0, "embedded": 0, "error": str(exc)}
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


def run_case_embedding_loop(interval_s: int = 300) -> None:
    """Spawn the background thread. Idempotent per-process."""
    global _loop_thread
    if _loop_thread is not None and _loop_thread.is_alive():
        logger.info("Case-embedding loop already running — skipping")
        return

    def _loop() -> None:
        logger.info(
            "Case-embedding background loop started (interval: %ds, model: %s)",
            interval_s,
            os.environ.get("ION_EMBEDDING_MODEL", DEFAULT_MODEL),
        )
        while not _stop_event.is_set():
            try:
                _tick()
            except Exception as exc:
                logger.warning("Case-embedding loop error: %s", exc)
            _stop_event.wait(interval_s)
        logger.info("Case-embedding loop stopped")

    _loop_thread = threading.Thread(
        target=_loop, daemon=True, name="ion-case-embedding"
    )
    _loop_thread.start()


def stop_case_embedding_loop() -> None:
    _stop_event.set()


def start_case_embedding_if_enabled(engine=None) -> bool:
    # Default off — opt in with ION_EMBEDDING_ENABLED=true. Matches
    # EmbeddingService.is_enabled so the background loop only spins up
    # when the site has made a conscious choice to run embeddings.
    enabled_env = os.environ.get("ION_EMBEDDING_ENABLED", "").lower()
    if enabled_env not in ("true", "1", "yes"):
        logger.info(
            "Case-embedding disabled (opt-in: set ION_EMBEDDING_ENABLED=true)"
        )
        return False

    try:
        interval_s = int(os.environ.get("ION_CASE_EMBEDDING_INTERVAL_S", "300"))
    except ValueError:
        interval_s = 300

    if engine is None:
        engine = get_engine(get_config().db_path)

    try:
        from ion.storage.database import LOCK_CASE_EMBEDDING_BG  # type: ignore
        lock_id = LOCK_CASE_EMBEDDING_BG
    except ImportError:
        lock_id = 1019

    def _start() -> None:
        run_case_embedding_loop(interval_s=interval_s)

    return run_locked(
        engine, lock_id, "case_embedding_bg_loop", _start, hold_until_close=True
    )


def get_last_run_info():
    with _last_run_lock:
        return _last_run_at, (dict(_last_result) if _last_result else None)
