"""Knowledge-base article embedding background producer.

Runs under advisory lock ``LOCK_KB_EMBEDDING_BG`` (1020). On each tick:

1. Find Document rows whose collection tree has "Knowledge Base" as the
   ancestor AND that either (a) have no ``KBChunkEmbedding`` rows yet,
   or (b) whose stored source_text_hash / model tag differs from current
   (doc edited, model changed, or chunking scheme bumped).
2. Split the doc into passage chunks (v0.51.0 — see ``_chunk_body``),
   embed each chunk via ``EmbeddingService``.
3. Replace the doc's ``KBChunkEmbedding`` rows atomically (delete + insert
   in one transaction per tick).

v0.51.0: chunk-level embedding replaces the whole-doc vector. The old
single vector lost long articles' tails (nomic end-truncation + an 8k input
cap) and retrieval could only quote the doc head. Chunks make every passage
retrievable and let the prompt carry the passage that matched.

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

from ion.core import apm
from ion.core.config import get_config
from ion.models.document import Document
from ion.models.kb_document_embedding import KBChunkEmbedding
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

# v0.51.0 chunking parameters. Target ≈1600 chars (≈400 tokens) sits well
# inside nomic-embed-text's window so no chunk is ever end-truncated, while
# staying passage-sized (a topic section, not a whole article). The overlap
# only applies when a single paragraph exceeds the target and must be
# hard-split — it keeps a sentence that straddles the cut represented in
# both halves. _MAX_CHUNKS_PER_DOC bounds a pathological article (64 chunks
# ≈ 100k chars) so one doc can't monopolise the embed batch forever.
# _CHUNK_SCHEME is folded into the staleness hash — bump it (c2, c3, …)
# whenever these parameters change so the whole corpus re-chunks once.
_CHUNK_TARGET_CHARS = 1600
_CHUNK_OVERLAP_CHARS = 200
_MAX_CHUNKS_PER_DOC = 64
_CHUNK_SCHEME = "c1"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _chunk_body(body: str) -> list[str]:
    """Split a document body into passage chunks.

    Greedy paragraph packing: paragraphs (split on blank lines) are packed
    into chunks up to ``_CHUNK_TARGET_CHARS``; a paragraph longer than the
    target is hard-split with ``_CHUNK_OVERLAP_CHARS`` of carry-over so a
    sentence straddling the cut stays represented in both halves. Deliberately
    simple — no markdown/heading awareness — so the chunk boundaries are
    stable and cheap to compute.
    """
    body = (body or "").strip()
    if not body:
        return []
    paragraphs = [p.strip() for p in body.split("\n\n") if p.strip()]
    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        if len(para) > _CHUNK_TARGET_CHARS:
            if current:
                chunks.append(current)
                current = ""
            start = 0
            while start < len(para):
                chunks.append(para[start:start + _CHUNK_TARGET_CHARS])
                if start + _CHUNK_TARGET_CHARS >= len(para):
                    break
                start += _CHUNK_TARGET_CHARS - _CHUNK_OVERLAP_CHARS
            continue
        if current and len(current) + 2 + len(para) > _CHUNK_TARGET_CHARS:
            chunks.append(current)
            current = para
        else:
            current = f"{current}\n\n{para}" if current else para
    if current:
        chunks.append(current)
    return chunks[:_MAX_CHUNKS_PER_DOC]


def _chunk_source_text(doc: Document, chunk: str) -> str:
    """The text actually embedded for one chunk.

    The title is prepended to EVERY chunk — it's high-signal topical context
    (standard passage-embedding practice) and keeps a mid-article chunk
    anchored to its subject.
    """
    parts = []
    if doc.name:
        parts.append(f"Title: {doc.name}")
    if chunk:
        parts.append(f"Content: {chunk}")
    return "\n".join(parts)


def _kb_doc_hash_input(doc: Document) -> str:
    """The staleness-hash input: whole doc + chunk-scheme marker.

    Hashing the FULL body (no cap) means any edit anywhere re-embeds the
    doc; folding in ``_CHUNK_SCHEME`` re-chunks the corpus once when the
    chunking parameters change.
    """
    return f"{_CHUNK_SCHEME}\nTitle: {doc.name or ''}\nContent: {doc.rendered_content or ''}"


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
    """One pass — chunk + embed new and stale KB documents. Batched.

    v0.51.0: the batch budget counts CHUNK embeds (Ollama calls), not docs,
    so a long article costs proportionally. A document is only ever written
    whole: if any of its chunks fails to embed, the doc is skipped this tick
    and retried next interval — no partial chunk sets. At least one doc is
    processed per tick even when its chunk count exceeds the remaining
    budget, so a single long article can't stall the queue forever.
    """
    try:
        batch_limit = int(os.environ.get("ION_KB_EMBEDDING_BATCH", "40"))
    except ValueError:
        batch_limit = 40

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
            .limit(max(batch_limit, 20) * 4)
        ).scalars().all()
    )

    # One representative row per doc is enough for the staleness check —
    # all of a doc's chunk rows share source_text_hash + model_name.
    doc_ids = [d.id for d in docs]
    existing: Dict[int, KBChunkEmbedding] = {}
    if doc_ids:
        for row in session.execute(
            select(KBChunkEmbedding).where(
                KBChunkEmbedding.document_id.in_(doc_ids),
                KBChunkEmbedding.chunk_index == 0,
            )
        ).scalars().all():
            existing[row.document_id] = row

    docs_embedded = chunks_embedded = skipped = failed_docs = scanned = 0
    for doc in docs:
        if chunks_embedded >= batch_limit:
            break
        scanned += 1
        hsh = _hash(_kb_doc_hash_input(doc))
        row = existing.get(doc.id)
        if (
            row is not None
            and row.source_text_hash == hsh
            and row.model_name == svc.model_tag
        ):
            skipped += 1
            continue

        chunks = _chunk_body(doc.rendered_content)
        if not chunks:
            continue

        # Embed every chunk BEFORE touching the stored rows — a mid-doc
        # Ollama failure must not leave a partial chunk set behind.
        vectors: list = []
        for chunk in chunks:
            vec = svc.embed(_chunk_source_text(doc, chunk), mode="document")
            if vec is None:
                vectors = None
                break
            vectors.append(vec)
        if vectors is None:
            failed_docs += 1
            if failed_docs >= 3:
                break
            continue

        now = datetime.now(timezone.utc)
        # "fetch" keeps the session identity map in sync — the re-inserted
        # rows reuse the deleted rows' composite PKs within one transaction.
        session.query(KBChunkEmbedding).filter(
            KBChunkEmbedding.document_id == doc.id
        ).delete(synchronize_session="fetch")
        for idx, (chunk, vec) in enumerate(zip(chunks, vectors)):
            session.add(
                KBChunkEmbedding(
                    document_id=doc.id,
                    chunk_index=idx,
                    chunk_text=chunk,
                    embedding=vec,
                    model_name=svc.model_tag,
                    embedded_at=now,
                    source_text_hash=hsh,
                )
            )
        docs_embedded += 1
        chunks_embedded += len(chunks)

    session.commit()
    return {
        "scanned": scanned,
        "embedded": docs_embedded,
        "chunks": chunks_embedded,
        "skipped_fresh": skipped,
        "failed": failed_docs,
        "model": svc.model,
    }


def _tick() -> Dict[str, Any]:
    factory = get_session_factory()
    session = factory()
    try:
        with apm.background_transaction("kb_embedding_loop"):
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
