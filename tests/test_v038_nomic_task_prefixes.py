"""v0.38.0 — nomic-embed-text task prefixes (asymmetric retrieval).

`nomic-embed-text` is asymmetric: stored corpus text must be embedded with a
``search_document: `` instruction and lookup text with ``search_query: ``.
ION previously embedded both sides as raw text. These tests pin:

1. `EmbeddingService.embed` prepends the correct task prefix per ``mode``.
2. The prefix is gated by ``ION_EMBEDDING_TASK_PREFIX`` (default on).
3. ``model_tag`` encodes the prefix regime so flipping it makes the stored
   corpus stale (the case/KB re-embed trigger compares against ``model_tag``).
4. ``mode`` is validated even when prefixes are disabled.
"""

from __future__ import annotations

import pytest

from ion.services.embedding_service import (
    DEFAULT_MODEL,
    EmbeddingService,
    _TASK_PREFIX_TAG,
)


class _FakeResponse:
    """Minimal stand-in for an httpx response carrying one embedding."""

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return {"embeddings": [[0.1, 0.2, 0.3]]}

    # expose what was POSTed so tests can assert on the prefixed input
    @property
    def sent(self):
        return self._payload


def _capture_post(monkeypatch):
    """Patch ``httpx.post`` in the embedding module; return a list that
    collects the JSON body of each call."""
    sent: list[dict] = []

    def _fake_post(url, json=None, timeout=None):  # noqa: A002 - mirror httpx sig
        sent.append(json)
        return _FakeResponse(json)

    monkeypatch.setattr(
        "ion.services.embedding_service.httpx.post", _fake_post
    )
    return sent


# --------------------------------------------------------------- model_tag


def test_model_tag_encodes_prefix_regime_by_default(monkeypatch):
    monkeypatch.delenv("ION_EMBEDDING_TASK_PREFIX", raising=False)
    svc = EmbeddingService(model=DEFAULT_MODEL)
    assert svc.use_task_prefix is True
    # The stored tag differs from the bare model name → any vector previously
    # stored under the bare name is now stale and re-embeds.
    assert svc.model_tag == f"{DEFAULT_MODEL}+{_TASK_PREFIX_TAG}"
    assert svc.model_tag != svc.model


def test_model_tag_falls_back_to_bare_model_when_disabled(monkeypatch):
    monkeypatch.setenv("ION_EMBEDDING_TASK_PREFIX", "false")
    svc = EmbeddingService(model=DEFAULT_MODEL)
    assert svc.use_task_prefix is False
    assert svc.model_tag == DEFAULT_MODEL


def test_disabling_then_enabling_prefix_changes_the_tag():
    """The mechanism that drives the corpus re-embed: stored rows tagged under
    one regime never match the other, so toggling forces a full re-embed."""
    off = EmbeddingService(model="m")
    off.use_task_prefix = False
    on = EmbeddingService(model="m")
    on.use_task_prefix = True
    assert off.model_tag != on.model_tag


# ----------------------------------------------------------- prefix on embed


def test_embed_query_prepends_search_query_prefix(monkeypatch):
    monkeypatch.setenv("ION_EMBEDDING_TASK_PREFIX", "true")
    sent = _capture_post(monkeypatch)
    svc = EmbeddingService(model=DEFAULT_MODEL)

    vec = svc.embed("brute force against host-01", mode="query")

    assert vec == [0.1, 0.2, 0.3]
    assert sent[0]["input"] == "search_query: brute force against host-01"
    assert sent[0]["model"] == DEFAULT_MODEL  # API call uses the bare model


def test_embed_document_prepends_search_document_prefix(monkeypatch):
    monkeypatch.setenv("ION_EMBEDDING_TASK_PREFIX", "true")
    sent = _capture_post(monkeypatch)
    svc = EmbeddingService(model=DEFAULT_MODEL)

    svc.embed("Title: Suspicious login", mode="document")

    assert sent[0]["input"] == "search_document: Title: Suspicious login"


def test_embed_defaults_to_document_mode(monkeypatch):
    monkeypatch.setenv("ION_EMBEDDING_TASK_PREFIX", "true")
    sent = _capture_post(monkeypatch)
    svc = EmbeddingService(model=DEFAULT_MODEL)

    svc.embed("some stored text")

    assert sent[0]["input"].startswith("search_document: ")


def test_embed_omits_prefix_when_disabled(monkeypatch):
    monkeypatch.setenv("ION_EMBEDDING_TASK_PREFIX", "false")
    sent = _capture_post(monkeypatch)
    svc = EmbeddingService(model=DEFAULT_MODEL)

    svc.embed("raw text", mode="query")

    assert sent[0]["input"] == "raw text"


# ------------------------------------------------------------ mode validation


@pytest.mark.parametrize("prefix_flag", ["true", "false"])
def test_embed_rejects_unknown_mode(monkeypatch, prefix_flag):
    """A typo'd mode must fail loudly regardless of the prefix gate, so a bad
    call site never silently embeds under the wrong regime."""
    monkeypatch.setenv("ION_EMBEDDING_TASK_PREFIX", prefix_flag)
    _capture_post(monkeypatch)
    svc = EmbeddingService(model=DEFAULT_MODEL)

    with pytest.raises(ValueError, match="mode must be"):
        svc.embed("text", mode="documnet")
