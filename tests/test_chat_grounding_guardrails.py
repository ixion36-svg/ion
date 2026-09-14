"""Chat's two anti-fabrication guardrails: sampling temperature and the grounding pass.

Both exist because a 7-8B model given substring-matched reference context at
conversational temperature invents specifics that look sourced. The failure is
silent -- a fabricated CVE reads exactly like a real one -- so these pin the
observable contract rather than the implementation.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ion.services.ai_context_service import ContextSnippet, RAGContext  # noqa: E402
from ion.services.chat_grounding_service import (  # noqa: E402
    _normalize_result,
    build_grounding_user_prompt,
    render_grounding_note,
    should_check,
    verify_chat_answer,
)
from ion.web.ai_api import ChatRequest  # noqa: E402

ANSWER = "x" * 300
CONTEXT = "--- REFERENCE CONTEXT ---\n[KB Article #1] Phishing\nbody\n"


# --------------------------------------------------------------------------
# Sampling temperature. Both UI callers omit the field, so the Pydantic
# default is what analysts actually get.
# --------------------------------------------------------------------------


def test_chat_temperature_default_is_low():
    """0.7 was the outlier: every other ION AI surface samples at 0.1-0.4."""
    assert ChatRequest.model_fields["temperature"].default == 0.3


def test_a_caller_can_still_ask_for_more_entropy():
    assert ChatRequest(messages=[], temperature=0.9).temperature == 0.9


def test_the_ceiling_still_holds():
    with pytest.raises(Exception):
        ChatRequest(messages=[], temperature=1.5)


# --------------------------------------------------------------------------
# The grounding contract in the RAG block.
# --------------------------------------------------------------------------


def test_reference_block_states_the_grounding_contract():
    block = RAGContext(
        snippets=[ContextSnippet("knowledge_base", 1, "Phishing", "body")]
    ).to_prompt_block()
    lowered = block.lower()
    assert "ground your answer" in lowered
    assert "verbatim" in lowered, "the no-invented-specifics clause is gone"
    assert "does not answer the question" in lowered, "the say-so-plainly clause is gone"


def test_empty_context_produces_no_block():
    """No retrieval means no contract to state and nothing to cite."""
    assert RAGContext(snippets=[]).to_prompt_block() == ""


# --------------------------------------------------------------------------
# Gating. The check must cost nothing when there is nothing to check.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("answer", "context", "expected"),
    [
        pytest.param(ANSWER, CONTEXT, True, id="claim-and-evidence"),
        pytest.param(ANSWER, "", False, id="no-evidence"),
        pytest.param("Sure, happy to help.", CONTEXT, False, id="too-short-to-claim"),
        pytest.param("", CONTEXT, False, id="empty"),
        pytest.param(ANSWER, "   ", False, id="whitespace-evidence"),
    ],
)
def test_should_check_gating(answer, context, expected):
    assert should_check(answer, context) is expected


class _Unreachable:
    """Any call proves the gate leaked."""

    enabled = True

    async def chat(self, **kwargs):
        raise AssertionError("verifier ran when it should have been skipped")


class _Fake:
    enabled = True

    def __init__(self, reply):
        self.reply = reply
        self.kwargs = None

    async def chat(self, **kwargs):
        self.kwargs = kwargs
        return {"content": self.reply}


@pytest.fixture
def flag_on(monkeypatch):
    from ion.core.config import get_config

    cfg = get_config()
    monkeypatch.setattr(cfg, "chat_grounding_check", True, raising=False)
    return cfg


def test_the_check_is_on_by_default(monkeypatch):
    """Graduated from opt-in 2026-09-14. Built from a clean env so the assertion
    reflects the code default, not whatever this process happens to have set."""
    import ion.core.config as config_mod

    monkeypatch.delenv("ION_CHAT_GROUNDING_CHECK", raising=False)
    monkeypatch.setattr(config_mod, "_config", None, raising=False)
    assert config_mod.get_config().chat_grounding_check is True


@pytest.mark.anyio
async def test_turning_it_off_spends_no_tokens(monkeypatch):
    """Off must not reach Ollama at all, not merely discard the result."""
    from ion.core.config import get_config

    monkeypatch.setattr(get_config(), "chat_grounding_check", False, raising=False)
    result = await verify_chat_answer(ANSWER, CONTEXT, ollama=_Unreachable())
    assert result == {"skipped": True, "grounded": None, "reason": "disabled"}


@pytest.mark.anyio
async def test_no_context_skips_without_calling(flag_on):
    result = await verify_chat_answer(ANSWER, "", ollama=_Unreachable())
    assert result["skipped"] and result["reason"] == "nothing-to-check"


@pytest.mark.anyio
async def test_ollama_disabled_is_a_silent_noop(flag_on):
    class Off:
        enabled = False

    result = await verify_chat_answer(ANSWER, CONTEXT, ollama=Off())
    assert result["skipped"] and result["reason"] == "ollama-disabled"


@pytest.mark.anyio
async def test_a_raising_backend_never_propagates(flag_on):
    """Breaker-open or timeout must annotate nothing, not break the response."""

    class Boom:
        enabled = True

        async def chat(self, **kwargs):
            raise RuntimeError("circuit breaker open")

    result = await verify_chat_answer(ANSWER, CONTEXT, ollama=Boom())
    assert result["skipped"] and result["reason"] == "ollama-unavailable"


@pytest.mark.anyio
async def test_unparseable_reply_is_a_noop_not_a_failure(flag_on):
    result = await verify_chat_answer(ANSWER, CONTEXT, ollama=_Fake("sorry, I cannot"))
    assert result["skipped"] and result["reason"] == "unparseable"


# --------------------------------------------------------------------------
# Result handling.
# --------------------------------------------------------------------------


@pytest.mark.anyio
async def test_the_check_runs_at_zero_temperature(flag_on):
    """An adjudicator that samples is a second opinion, not a check."""
    fake = _Fake('{"grounded": true, "unsupported_claims": []}')
    await verify_chat_answer(ANSWER, CONTEXT, ollama=fake)
    assert fake.kwargs["temperature"] == 0.0
    assert fake.kwargs["response_format"] == "json"


@pytest.mark.anyio
async def test_fenced_json_is_tolerated(flag_on):
    fake = _Fake('```json\n{"grounded": false, "unsupported_claims": ["CVE-2024-1337"]}\n```')
    result = await verify_chat_answer(ANSWER, CONTEXT, ollama=fake)
    assert result["skipped"] is False
    assert result["grounded"] is False
    assert result["unsupported_claims"] == ["CVE-2024-1337"]


def test_claims_without_a_verdict_still_count_as_ungrounded():
    """A model that lists claims but omits `grounded` answered the real question."""
    assert _normalize_result({"unsupported_claims": ["T1055"]})["grounded"] is False


def test_a_clean_answer_is_grounded():
    assert _normalize_result({"grounded": True, "unsupported_claims": []})["grounded"] is True


def test_claims_are_capped_and_stringified():
    out = _normalize_result({"unsupported_claims": [f"c{i}" for i in range(50)] + ["", "  "]})
    assert len(out["unsupported_claims"]) == 20
    assert all(isinstance(c, str) and c for c in out["unsupported_claims"])


def test_string_booleans_are_coerced():
    assert _normalize_result({"grounded": "yes"})["grounded"] is True
    assert _normalize_result({"grounded": "false"})["grounded"] is False


# --------------------------------------------------------------------------
# Prompt + rendering.
# --------------------------------------------------------------------------


def test_both_evidence_halves_reach_the_prompt():
    prompt = build_grounding_user_prompt("the answer text", "the context text")
    assert "the answer text" in prompt
    assert "the context text" in prompt
    assert prompt.index("the context text") < prompt.index("the answer text")


def test_oversized_inputs_are_capped():
    """An untruncated transcript would push the evidence out of the context window."""
    prompt = build_grounding_user_prompt("a" * 50_000, "b" * 50_000)
    assert len(prompt) < 20_000


def test_skipped_results_render_nothing():
    assert render_grounding_note({"skipped": True}) == ""
    assert render_grounding_note({}) == ""


def test_unsupported_claims_are_named_in_the_note():
    note = render_grounding_note(
        {"skipped": False, "grounded": False, "unsupported_claims": ["CVE-2024-1337"]}
    )
    assert "CVE-2024-1337" in note
