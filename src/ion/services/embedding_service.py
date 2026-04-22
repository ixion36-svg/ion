"""Ollama embedding wrapper.

Thin client around Ollama's ``/api/embed`` endpoint, defaulting to
``nomic-embed-text`` (768-dim). Used by the case-embedding background task
and (future) KB RAG grounding.

Design:
  * Graceful degradation — if Ollama is unreachable or the model isn't
    pulled, ``embed()`` returns None and logs a warning. Callers skip
    writing the embedding and try again next tick.
  * Synchronous — the background task already runs in its own thread under
    an advisory lock; async would just add event-loop ceremony.
  * Small timeout (30 s) — embedding a ~1 KB blob should be sub-second on
    `nomic-embed-text`; if it takes longer something's wrong and we'd
    rather skip the batch.
"""

from __future__ import annotations

import logging
import os
from typing import List, Optional

import httpx

logger = logging.getLogger(__name__)


# Defaults — overridable via env. 768 dims matches nomic-embed-text.
DEFAULT_MODEL = "nomic-embed-text"
DEFAULT_DIM = 768


class EmbeddingService:
    """Ollama embedding client."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.base_url = (
            base_url
            or os.environ.get("ION_OLLAMA_URL")
            or "http://ion-ollama:11434"
        ).rstrip("/")
        self.model = model or os.environ.get(
            "ION_EMBEDDING_MODEL", DEFAULT_MODEL
        )
        self.timeout = timeout

    @property
    def is_enabled(self) -> bool:
        """Default off — opt in with ``ION_EMBEDDING_ENABLED=true``.

        Case-similarity embeddings require an Ollama deployment with
        ``nomic-embed-text`` pulled (~300 MB). Air-gapped sites without a
        local LLM host should stay at the default (disabled) — the
        similarity sidebar degrades gracefully with a "no similar cases"
        hint, and nothing else breaks.
        """
        flag = os.environ.get("ION_EMBEDDING_ENABLED", "").lower()
        return flag in ("true", "1", "yes")

    def embed(self, text: str) -> Optional[List[float]]:
        """Embed ``text``. Returns None on any failure — never raises.

        The caller is expected to retry on a later tick (the background
        embedder runs every 5 min by default). Silent failure keeps a
        transient Ollama outage from logging-storm.
        """
        if not self.is_enabled:
            return None
        if not text or not text.strip():
            return None
        try:
            resp = httpx.post(
                f"{self.base_url}/api/embed",
                json={"model": self.model, "input": text},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.debug(
                "Embedding call failed for model=%s: %s", self.model, exc
            )
            return None

        # Ollama /api/embed returns {"embeddings": [[...]]} (list of lists,
        # one per input — we only sent one input).
        embeddings = data.get("embeddings") if isinstance(data, dict) else None
        if isinstance(embeddings, list) and embeddings:
            first = embeddings[0]
            if isinstance(first, list) and first:
                return [float(x) for x in first]
        # Fall back to the older /api/embeddings response shape
        # ({"embedding": [...]}) — some Ollama builds still use it.
        singular = data.get("embedding") if isinstance(data, dict) else None
        if isinstance(singular, list) and singular:
            return [float(x) for x in singular]
        logger.debug("Unexpected Ollama embedding response: %r", data)
        return None


# Singleton pattern matches the rest of ION's services.
_embedding_service: Optional[EmbeddingService] = None


def get_embedding_service() -> EmbeddingService:
    global _embedding_service
    if _embedding_service is None:
        _embedding_service = EmbeddingService()
    return _embedding_service
