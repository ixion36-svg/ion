"""Playbook embedding background producer.

Runs under advisory lock ``LOCK_PLAYBOOK_EMBEDDING_BG`` (1027). On each
tick:

1. Find active Playbook rows that either (a) have no ``PlaybookEmbedding``
   row yet, or (b) whose source_text_hash / model tag differs from current
   (playbook edited, model or prefix regime changed).
2. Embed the playbook's name + description + trigger conditions + step
   titles/descriptions via ``EmbeddingService``.
3. Upsert the ``PlaybookEmbedding`` row.

v0.51.0: this feeds the FALLBACK arm of the Playbook RAG layer — the
primary arm is the deterministic structured matcher (rule patterns /
MITRE), which works with no vectors at all. Inactive playbooks are not
embedded (retrieval must never suggest a disabled procedure); a playbook
flipped inactive has its row deleted on the next tick.

Default ON alongside the other RAG layers; disable with
``ION_PLAYBOOK_RAG_ENABLED=false``. Graceful no-op without Ollama.

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
from ion.models.playbook import Playbook
from ion.models.playbook_embedding import PlaybookEmbedding
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


def _playbook_source_text(playbook: Playbook) -> str:
    """Build the text we embed for a playbook.

    Name + description carry the topic; the trigger conditions (rule
    patterns, MITRE techniques/tactics) anchor it to the alert vocabulary
    the query vector uses; step titles/descriptions describe the procedure.
    Per-section clips keep one verbose field from crowding out the rest.
    """
    parts = [f"Playbook: {playbook.name}"]
    if playbook.description:
        parts.append(f"Description: {str(playbook.description)[:800]}")

    cond = playbook.trigger_conditions or {}
    if isinstance(cond, dict):
        rules = cond.get("rule_patterns")
        if isinstance(rules, list) and rules:
            parts.append("Rules: " + ", ".join(str(r) for r in rules[:10]))
        mitre = cond.get("mitre_techniques")
        if isinstance(mitre, list) and mitre:
            parts.append("MITRE: " + ", ".join(str(t) for t in mitre[:12]))
        tactics = cond.get("mitre_tactics")
        if isinstance(tactics, list) and tactics:
            parts.append("Tactics: " + ", ".join(str(t) for t in tactics[:8]))

    steps = sorted(playbook.steps or [], key=lambda s: s.step_order or 0)
    for step in steps[:15]:
        line = f"Step: {step.title}"
        if step.description:
            line += f" — {str(step.description)[:200]}"
        parts.append(line)
    return "\n".join(parts)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# Core tick
# ---------------------------------------------------------------------------


def run_playbook_embedding_once(session: Session) -> Dict[str, Any]:
    """One pass — embed new + stale active playbooks; drop inactive rows.

    Playbook counts are small (dozens), so no doc-style batching: the whole
    catalogue is scanned every tick and the skip-fresh path makes steady
    state a cheap no-op.
    """
    svc = get_embedding_service()
    if not svc.is_enabled:
        return {"scanned": 0, "embedded": 0, "disabled": True}

    playbooks = (
        session.execute(select(Playbook)).scalars().all()
    )
    existing: Dict[int, PlaybookEmbedding] = {
        row.playbook_id: row
        for row in session.execute(select(PlaybookEmbedding)).scalars().all()
    }

    embedded = skipped = failed = removed = scanned = 0
    for pb in playbooks:
        scanned += 1
        row = existing.get(pb.id)
        if not pb.is_active:
            # Never serve a disabled procedure via similarity.
            if row is not None:
                session.delete(row)
                removed += 1
            continue
        source = _playbook_source_text(pb)
        if not source:
            continue
        hsh = _hash(source)
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
                PlaybookEmbedding(
                    playbook_id=pb.id,
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
        "removed_inactive": removed,
        "failed": failed,
        "model": svc.model,
    }


def _tick() -> Dict[str, Any]:
    factory = get_session_factory()
    session = factory()
    try:
        with apm.background_transaction("playbook_embedding_loop"):
            summary = run_playbook_embedding_once(session)
    except Exception as exc:
        logger.exception("Playbook embedding tick crashed: %s", exc)
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


def run_playbook_embedding_loop(interval_s: int = 600) -> None:
    global _loop_thread
    if _loop_thread is not None and _loop_thread.is_alive():
        logger.info("Playbook embedding loop already running — skipping")
        return

    def _loop() -> None:
        logger.info(
            "Playbook embedding background loop started (interval: %ds, model: %s)",
            interval_s,
            os.environ.get("ION_EMBEDDING_MODEL", DEFAULT_MODEL),
        )
        while not _stop_event.is_set():
            try:
                _tick()
            except Exception as exc:
                logger.warning("Playbook embedding loop error: %s", exc)
            _stop_event.wait(interval_s)
        logger.info("Playbook embedding loop stopped")

    _loop_thread = threading.Thread(
        target=_loop, daemon=True, name="ion-playbook-embedding"
    )
    _loop_thread.start()


def stop_playbook_embedding_loop() -> None:
    _stop_event.set()


def start_playbook_embedding_if_enabled(engine=None) -> bool:
    """Gated by ION_PLAYBOOK_RAG_ENABLED — default ON, same philosophy as
    the other RAG layers (v0.36.0). Disable with =false. The deterministic
    matcher arm of the Playbook RAG layer works regardless of this loop —
    only the similarity FALLBACK needs the vectors this produces."""
    enabled_env = os.environ.get("ION_PLAYBOOK_RAG_ENABLED", "true").lower()
    if enabled_env not in ("true", "1", "yes"):
        logger.info(
            "Playbook embedding disabled (set ION_PLAYBOOK_RAG_ENABLED=false to opt out)"
        )
        return False

    try:
        interval_s = int(os.environ.get("ION_PLAYBOOK_EMBEDDING_INTERVAL_S", "600"))
    except ValueError:
        interval_s = 600

    if engine is None:
        engine = get_engine(get_config().db_path)

    try:
        from ion.storage.database import LOCK_PLAYBOOK_EMBEDDING_BG  # type: ignore
        lock_id = LOCK_PLAYBOOK_EMBEDDING_BG
    except ImportError:
        lock_id = 1027

    def _start() -> None:
        run_playbook_embedding_loop(interval_s=interval_s)

    return run_locked(
        engine, lock_id, "playbook_embedding_bg_loop", _start, hold_until_close=True
    )


def get_last_run_info():
    with _last_run_lock:
        return _last_run_at, (dict(_last_result) if _last_result else None)
