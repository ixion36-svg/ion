"""Knowledge-base article embedding background producer.

Runs under advisory lock ``LOCK_KB_EMBEDDING_BG`` (1020). On each tick:

1. Find Document rows whose collection tree has "Knowledge Base" as the
   ancestor AND that either (a) have no ``KBDocumentEmbedding`` row yet,
   or (b) whose source_text_hash differs from the current hash (doc edited).
2. Embed the doc's ``name + rendered_content`` via ``EmbeddingService``.
3. Upsert the ``KBDocumentEmbedding`` row.

Default ON (v0.36.0); disable with ``ION_KB_RAG_ENABLED=false``. KB
embedding is a graceful no-op without Ollama (same prerequisite as case
embedding) — it self-activates once an Ollama host is reachable.

Air-gapped friendly: only depends on local Ollama + local Postgres.
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
from ion.models.document import Document
from ion.models.kb_document_embedding import KBDocumentEmbedding
from ion.models.template import Collection
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

# Max characters of rendered content to embed. nomic-embed-text has an
# 8192-token context window; at ~4 chars/token that's ~32k chars, but most
# KB articles are well under 6k. We cap at 8k to keep embeddings stable
# across edits (trailing-text changes below the cap don't shift the vector).
_MAX_BODY_CHARS = 8000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _kb_source_text(doc: Document) -> str:
    """Build the text we embed for a KB document.

    Title is high-signal (often a question or topic); body adds detail.
    Kept simple — no structure-aware parsing, just prefix-and-concat.
    """
    body = (doc.rendered_content or "")[:_MAX_BODY_CHARS]
    parts = []
    if doc.name:
        parts.append(f"Title: {doc.name}")
    if body:
        parts.append(f"Content: {body}")
    return "\n".join(parts)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _get_kb_root_id(session: Session) -> Optional[int]:
    """Return the id of the top-level "Knowledge Base" collection, or None
    if it hasn't been seeded yet (fresh deploys).

    Tolerant of a duplicated root: if more than one top-level collection is
    named "Knowledge Base" (e.g. seeded twice across deploys), pick the earliest
    deterministically rather than raising ``MultipleResultsFound`` — that
    exception was crashing the KB-embedding background tick on every cycle.
    """
    rows = (
        session.query(Collection.id)
        .filter(Collection.name == "Knowledge Base")
        .filter(Collection.parent_id.is_(None))
        .order_by(Collection.id.asc())
        .all()
    )
    if not rows:
        return None
    if len(rows) > 1:
        logger.warning(
            "kb_embedding: %d top-level 'Knowledge Base' collections found; "
            "using the earliest (id=%s). Consider de-duplicating.",
            len(rows), rows[0][0],
        )
    return rows[0][0]


def _descendant_collection_ids(session: Session, root_id: int) -> set[int]:
    """All collection ids under the KB root (recursive).

    Single recursive CTE keeps this cheap even as KB grows.
    """
    from sqlalchemy import text as sql_text
    rows = session.execute(
        sql_text(
            """
            WITH RECURSIVE kb_tree(id) AS (
                SELECT :root
                UNION ALL
                SELECT c.id FROM collections c
                JOIN kb_tree t ON c.parent_id = t.id
            )
            SELECT id FROM kb_tree
            """
        ),
        {"root": root_id},
    ).all()
    return {r[0] for r in rows}


# ---------------------------------------------------------------------------
# Core tick
# ---------------------------------------------------------------------------


def run_kb_embedding_once(session: Session) -> Dict[str, Any]:
    """One pass — embed new + stale KB documents. Batched."""
    try:
        batch_limit = int(os.environ.get("ION_KB_EMBEDDING_BATCH", "20"))
    except ValueError:
        batch_limit = 20

    svc = get_embedding_service()
    if not svc.is_enabled:
        return {"scanned": 0, "embedded": 0, "disabled": True}

    kb_root = _get_kb_root_id(session)
    if kb_root is None:
        return {"scanned": 0, "embedded": 0, "no_kb_root": True}

    kb_collection_ids = _descendant_collection_ids(session, kb_root)
    if not kb_collection_ids:
        return {"scanned": 0, "embedded": 0, "empty_kb_tree": True}

    docs = (
        session.execute(
            select(Document)
            .where(Document.collection_id.in_(list(kb_collection_ids)))
            .where(Document.status == "active")
            .order_by(Document.id.desc())
            .limit(batch_limit * 4)
        ).scalars().all()
    )

    doc_ids = [d.id for d in docs]
    existing: Dict[int, KBDocumentEmbedding] = {}
    if doc_ids:
        existing = {
            row.document_id: row
            for row in session.execute(
                select(KBDocumentEmbedding).where(
                    KBDocumentEmbedding.document_id.in_(doc_ids)
                )
            ).scalars().all()
        }

    embedded = skipped = failed = scanned = 0
    for doc in docs:
        if embedded >= batch_limit:
            break
        scanned += 1
        source = _kb_source_text(doc)
        if not source:
            continue
        hsh = _hash(source)
        row = existing.get(doc.id)
        if (
            row is not None
            and row.source_text_hash == hsh
            and row.model_name == svc.model_tag
        ):
            skipped += 1
            continue

        vec = svc.embed(source, mode="document")
        if vec is None:
            failed += 1
            if failed >= 3:
                break
            continue

        now = datetime.now(timezone.utc)
        if row is None:
            session.add(
                KBDocumentEmbedding(
                    document_id=doc.id,
                    embedding=vec,
                    model_name=svc.model_tag,
                    embedded_at=now,
                    source_text_hash=hsh,
                )
            )
        else:
            row.embedding = vec
            row.model_name = svc.model_tag
            row.embedded_at = now
            row.source_text_hash = hsh
        embedded += 1

    session.commit()
    return {
        "scanned": scanned,
        "embedded": embedded,
        "skipped_fresh": skipped,
        "failed": failed,
        "model": svc.model,
    }


def _tick() -> Dict[str, Any]:
    factory = get_session_factory()
    session = factory()
    try:
        summary = run_kb_embedding_once(session)
    except Exception as exc:
        logger.exception("KB embedding tick crashed: %s", exc)
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


def run_kb_embedding_loop(interval_s: int = 300) -> None:
    global _loop_thread
    if _loop_thread is not None and _loop_thread.is_alive():
        logger.info("KB embedding loop already running — skipping")
        return

    def _loop() -> None:
        logger.info(
            "KB embedding background loop started (interval: %ds, model: %s)",
            interval_s,
            os.environ.get("ION_EMBEDDING_MODEL", DEFAULT_MODEL),
        )
        while not _stop_event.is_set():
            try:
                _tick()
            except Exception as exc:
                logger.warning("KB embedding loop error: %s", exc)
            _stop_event.wait(interval_s)
        logger.info("KB embedding loop stopped")

    _loop_thread = threading.Thread(
        target=_loop, daemon=True, name="ion-kb-embedding"
    )
    _loop_thread.start()


def stop_kb_embedding_loop() -> None:
    _stop_event.set()


def start_kb_embedding_if_enabled(engine=None) -> bool:
    """KB RAG is gated by ION_KB_RAG_ENABLED — default ON (v0.36.0), same
    pattern as case embedding. Disable with ION_KB_RAG_ENABLED=false."""
    enabled_env = os.environ.get("ION_KB_RAG_ENABLED", "true").lower()
    if enabled_env not in ("true", "1", "yes"):
        logger.info("KB embedding disabled (set ION_KB_RAG_ENABLED=false to opt out)")
        return False

    try:
        interval_s = int(os.environ.get("ION_KB_EMBEDDING_INTERVAL_S", "300"))
    except ValueError:
        interval_s = 300

    if engine is None:
        engine = get_engine(get_config().db_path)

    try:
        from ion.storage.database import LOCK_KB_EMBEDDING_BG  # type: ignore
        lock_id = LOCK_KB_EMBEDDING_BG
    except ImportError:
        lock_id = 1020

    def _start() -> None:
        run_kb_embedding_loop(interval_s=interval_s)

    return run_locked(
        engine, lock_id, "kb_embedding_bg_loop", _start, hold_until_close=True
    )


def get_last_run_info():
    with _last_run_lock:
        return _last_run_at, (dict(_last_result) if _last_result else None)
