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

Air-gapped or specific-version deployments can side-load a GGUF directly
into Ollama via ``scripts/ollama_import_gguf.sh`` (v0.16.2). The wrapper
itself doesn't change — set ``ION_EMBEDDING_MODEL`` to whatever name you
gave the imported model (e.g. ``nomic-embed-text-v1.5``).
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


# Task-instruction prefixes for nomic-embed-text (v0.38.0).
#
# nomic-embed-text(-v1.5) is an *asymmetric* retrieval model: it was trained
# with a task instruction prepended to every input. Stored corpus text wants
# ``search_document: `` and the lookup string wants ``search_query: ``.
# Supplying them puts queries and documents in the geometry the model learned
# for retrieval, measurably improving ranking. A model that does NOT understand
# the prefixes would embed them as literal tokens and degrade — so this is
# gated by ``ION_EMBEDDING_TASK_PREFIX`` (default on; set =false for such a
# model). See ``model_tag`` for how toggling it triggers a corpus re-embed.
_TASK_PREFIX_QUERY = "search_query: "
_TASK_PREFIX_DOCUMENT = "search_document: "

# Scheme marker appended to the stored ``model_name`` when prefixes are active.
# The case/KB re-embed loops skip a row only when source-hash AND model_name
# both match the current service, so encoding the prefix regime into the stored
# tag makes every vector stale the moment prefixes flip — the whole corpus
# re-embeds under one consistent regime. Bump to ``tp2`` etc. if the prefix
# scheme ever changes again.
_TASK_PREFIX_TAG = "tp1"


def _clip(value: object, max_chars: int) -> str:
    """Trim a value to ``max_chars`` for inclusion in an embedding blob.

    nomic-embed-text truncates input at its context window (~2048 tokens)
    *silently from the end* — so an unbounded field (a long AI summary, say)
    can push later sections out of the vector entirely. Per-section clipping
    keeps every section represented. Non-str values are stringified first.
    """
    s = value if isinstance(value, str) else str(value)
    s = s.strip()
    return s[:max_chars] if max_chars and len(s) > max_chars else s


def format_enrichment_digest(enrichment: object, *, max_chars: int = 400) -> str:
    """Compact one-line digest of TI enrichment verdicts for embedding text.

    Enrichment shape (per ``investigation_service``) is
    ``{kind: {indicator: context}}`` with ``kind`` in ip/domain/url/hash.
    We emit ``kind: indicator (context…); …`` with each context clipped and
    the whole digest capped at ``max_chars`` so one verbose enrichment field
    cannot dominate the embedding. Non-dict / empty → "".

    v0.50.1: moved here from ``alert_prompt_service`` so the alert query
    vector and the stored case vector digest enrichment identically —
    same centralisation rationale as ``format_core_embedding_sections``.
    """
    if not isinstance(enrichment, dict):
        return ""
    bits: list[str] = []
    for kind, hits in enrichment.items():
        if not isinstance(hits, dict) or not hits:
            continue
        inds = []
        for ind, ctx in hits.items():
            ctx_str = ctx if isinstance(ctx, str) else str(ctx)
            inds.append(f"{ind} ({ctx_str[:60]})" if ctx_str else str(ind))
        if inds:
            bits.append(f"{kind}: " + ", ".join(inds))
    return "; ".join(bits)[:max_chars]


def format_core_embedding_sections(
    *,
    title: object = None,
    description: object = None,
    hosts: object = None,
    users: object = None,
    rules: object = None,
    description_cap: int = 1000,
) -> list[str]:
    """Canonical core sections for the RAG embedding text.

    Both the alert query vector (``alert_prompt_service._alert_text_for_
    embedding``) and the stored case vector (``case_embedding_service.
    _case_source_text``) emit these five sections, in this order, so an
    alert vector stays directly comparable to case vectors. Centralised
    here so the two builders cannot silently drift out of alignment.

    Values are pre-extracted/pre-joined by each caller (their source shapes
    differ — dict keys vs ORM list attrs); this owns only the label set,
    order, and the description cap. Falsy values are skipped.
    """
    parts: list[str] = []
    if title:
        parts.append(f"Title: {title}")
    if description:
        parts.append(f"Description: {_clip(description, description_cap)}")
    if hosts:
        parts.append(f"Hosts: {hosts}")
    if users:
        parts.append(f"Users: {users}")
    if rules:
        parts.append(f"Rules: {rules}")
    return parts


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
        self.use_task_prefix = os.environ.get(
            "ION_EMBEDDING_TASK_PREFIX", "true"
        ).lower() in ("true", "1", "yes")

    @property
    def is_enabled(self) -> bool:
        """Default ON (v0.36.0) — disable with ``ION_EMBEDDING_ENABLED=false``.

        Case-similarity embeddings require an Ollama deployment with
        ``nomic-embed-text`` pulled (~300 MB). When Ollama is absent the
        feature degrades gracefully: ``embed()`` returns None on every
        call, the background loop no-ops, and the similarity sidebar shows
        a "no similar cases" hint — nothing breaks. Defaulting on means a
        site that DOES run Ollama gets case similarity + RAG with zero
        extra configuration; air-gapped sites without an LLM host pay only
        a cheap, silent no-op per embedding tick.
        """
        flag = os.environ.get("ION_EMBEDDING_ENABLED", "true").lower()
        return flag in ("true", "1", "yes")

    @property
    def model_tag(self) -> str:
        """The value stored in ``CaseEmbedding``/``KBChunkEmbedding``.

        ``model_name`` and used as the re-embed trigger. It is the raw Ollama
        model name plus a marker for the task-prefix regime, so query and
        document vectors are only ever compared when they were embedded under
        the *same* prefix scheme. Toggling ``ION_EMBEDDING_TASK_PREFIX``
        therefore makes the whole stored corpus stale and re-embeds it; the
        actual Ollama API call still uses the bare ``self.model``.
        """
        return f"{self.model}+{_TASK_PREFIX_TAG}" if self.use_task_prefix else self.model

    def _apply_task_prefix(self, text: str, mode: str) -> str:
        """Prepend the nomic task instruction for ``mode`` when enabled.

        ``mode`` is validated even when prefixes are off so a typo'd call site
        (e.g. ``mode="documnet"``) fails loudly in tests rather than silently
        embedding under the wrong regime.
        """
        if mode not in ("query", "document"):
            raise ValueError(
                f"embed mode must be 'query' or 'document', got {mode!r}"
            )
        if not self.use_task_prefix:
            return text
        prefix = _TASK_PREFIX_QUERY if mode == "query" else _TASK_PREFIX_DOCUMENT
        return f"{prefix}{text}"

    def embed(self, text: str, *, mode: str = "document") -> Optional[List[float]]:
        """Embed ``text``. Returns None on any failure — never raises.

        ``mode`` selects the nomic task prefix: ``"query"`` for a live lookup
        string (alert → similar cases / KB) and ``"document"`` for stored
        corpus text (case + KB vectors). Defaults to ``"document"`` so an
        un-annotated call stores rather than mis-tags as a query.

        The caller is expected to retry on a later tick (the background
        embedder runs every 5 min by default). Silent failure keeps a
        transient Ollama outage from logging-storm.
        """
        if not self.is_enabled:
            return None
        if not text or not text.strip():
            return None
        payload = self._apply_task_prefix(text, mode)
        try:
            resp = httpx.post(
                f"{self.base_url}/api/embed",
                json={"model": self.model, "input": payload},
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
