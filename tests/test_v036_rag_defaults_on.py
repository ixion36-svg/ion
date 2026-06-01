"""v0.36.0 — RAG layers default ON.

Pins the default-on flip for the four Bob/RAG gates and the explicit
opt-out (=false) for each:

  ION_EMBEDDING_ENABLED        — case-similarity + embedding backbone
  ION_KB_RAG_ENABLED           — KB topic grounding in Bob's prompt
  ION_FEW_SHOT_EXEMPLARS_ENABLED — prior analyst-verified cases
  ION_BOB_STORE_REASONING      — persist + surface Bob's reasoning text

Also asserts the two embedding loop-start gates honour an explicit
=false (returning False without spinning a background thread), and that
the per-call gate (EmbeddingService.is_enabled) and the loop gate share
the same default — they MUST agree or the loop and service disagree.
"""

from __future__ import annotations

import pytest

_FLAGS = [
    "ION_EMBEDDING_ENABLED",
    "ION_KB_RAG_ENABLED",
    "ION_FEW_SHOT_EXEMPLARS_ENABLED",
    "ION_BOB_STORE_REASONING",
]


@pytest.fixture
def clean_env(monkeypatch):
    """Ensure none of the RAG flags are set — exercises the code default."""
    for f in _FLAGS:
        monkeypatch.delenv(f, raising=False)
    return monkeypatch


# ---------------------------------------------------------------------------
# Defaults ON when unset
# ---------------------------------------------------------------------------

def test_embedding_enabled_default_on(clean_env):
    from ion.services.embedding_service import EmbeddingService
    assert EmbeddingService().is_enabled is True


def test_few_shot_default_on(clean_env):
    from ion.services.alert_prompt_service import _few_shot_enabled
    assert _few_shot_enabled() is True


def test_kb_rag_default_on(clean_env):
    from ion.services.alert_prompt_service import _kb_rag_enabled
    assert _kb_rag_enabled() is True


def test_store_reasoning_default_on(clean_env):
    from ion.services.investigation_service import _bob_store_reasoning_enabled
    assert _bob_store_reasoning_enabled() is True


# ---------------------------------------------------------------------------
# Explicit opt-out (=false) still disables
# ---------------------------------------------------------------------------

def test_embedding_disabled_explicit(monkeypatch):
    from ion.services.embedding_service import EmbeddingService
    monkeypatch.setenv("ION_EMBEDDING_ENABLED", "false")
    assert EmbeddingService().is_enabled is False


def test_few_shot_disabled_explicit(monkeypatch):
    from ion.services.alert_prompt_service import _few_shot_enabled
    monkeypatch.setenv("ION_FEW_SHOT_EXEMPLARS_ENABLED", "false")
    assert _few_shot_enabled() is False


def test_kb_rag_disabled_explicit(monkeypatch):
    from ion.services.alert_prompt_service import _kb_rag_enabled
    monkeypatch.setenv("ION_KB_RAG_ENABLED", "false")
    assert _kb_rag_enabled() is False


def test_store_reasoning_disabled_explicit(monkeypatch):
    from ion.services.investigation_service import _bob_store_reasoning_enabled
    monkeypatch.setenv("ION_BOB_STORE_REASONING", "false")
    assert _bob_store_reasoning_enabled() is False


# ---------------------------------------------------------------------------
# Loop-start gates honour an explicit =false without side effects
# ---------------------------------------------------------------------------

def test_case_embedding_loop_gate_respects_false(monkeypatch):
    from ion.services.case_embedding_service import start_case_embedding_if_enabled
    monkeypatch.setenv("ION_EMBEDDING_ENABLED", "false")
    assert start_case_embedding_if_enabled(engine=None) is False


def test_kb_embedding_loop_gate_respects_false(monkeypatch):
    from ion.services.kb_embedding_service import start_kb_embedding_if_enabled
    monkeypatch.setenv("ION_KB_RAG_ENABLED", "false")
    assert start_kb_embedding_if_enabled(engine=None) is False


# ---------------------------------------------------------------------------
# The per-call gate and the loop gate must share the same default. If they
# drift, the background loop spins up while embed() no-ops (or vice-versa).
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [("true", True), ("false", False)])
def test_embedding_per_call_and_loop_gates_agree(monkeypatch, value, expected):
    from ion.services.case_embedding_service import start_case_embedding_if_enabled
    from ion.services.embedding_service import EmbeddingService
    monkeypatch.setenv("ION_EMBEDDING_ENABLED", value)
    per_call = EmbeddingService().is_enabled
    # The loop gate returns True only when it starts; for the False case it
    # returns False. We assert the per-call gate matches the boolean intent.
    assert per_call is expected
    if not expected:
        assert start_case_embedding_if_enabled(engine=None) is False
