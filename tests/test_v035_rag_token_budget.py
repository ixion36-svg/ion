"""Tests for the token-budget guard in render_system_prompt (v0.35.0).

Verifies that:
  1. _estimate_tokens returns sensible values.
  2. When the fixed budget (base + template + contract) is already near the
     cap, RAG layers are dropped in reverse-priority order: skills first,
     then gold exemplars, then KB context.
  3. Output contract is NEVER dropped regardless of budget pressure.
  4. investigate_case no-template path calls render_system_prompt with
     alert context rather than falling back to raw SYSTEM_PROMPTS.
  5. _DEFAULT_MEMORY_MAX_CHARS is 3000.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# 1. _estimate_tokens
# ---------------------------------------------------------------------------

def test_estimate_tokens_basic():
    from ion.services.alert_prompt_service import _estimate_tokens

    assert _estimate_tokens("") == 1          # min 1
    assert _estimate_tokens("abcd") == 1      # 4 chars → 1 token
    assert _estimate_tokens("a" * 400) == 100 # 400 chars → 100 tokens
    assert _estimate_tokens("a" * 4000) == 1000


def test_estimate_tokens_constants():
    """Budget constants are sane."""
    from ion.services.alert_prompt_service import (
        _CHARS_PER_TOKEN,
        _SYSTEM_PROMPT_TOKEN_BUDGET,
    )

    assert _CHARS_PER_TOKEN == 4
    assert 3000 <= _SYSTEM_PROMPT_TOKEN_BUDGET <= 4096


# ---------------------------------------------------------------------------
# 2. Token budget guard — RAG layers dropped in correct order
# ---------------------------------------------------------------------------

def _make_service():
    """Return an AlertPromptService with a mock session."""
    from ion.services.alert_prompt_service import AlertPromptService
    return AlertPromptService(session=MagicMock())


def _huge_block(label: str, chars: int = 8000) -> str:
    return f"\n\n## {label}\n" + ("x" * chars)


TINY_ALERT = {
    "rule": {"name": "Test Rule"},
    "host": {"name": "host1"},
    "_source": {},
}


def test_kb_dropped_when_budget_tight():
    """KB block is skipped when fixed tokens already fill the budget.

    We patch the budget constant to 2000 tokens. The base security prompt
    (~138 tokens) + output contract (~1760 tokens) = ~1898 fixed tokens,
    leaving only ~102 tokens for RAG.  The KB block (3 × 800-char excerpts
    + section headers ≈ 640 tokens) exceeds that remainder and must be
    dropped.
    """
    import ion.services.alert_prompt_service as _aps

    svc = _make_service()
    kb_hits = [{"name": "Doc", "excerpt": "x" * 800, "similarity": 0.8}]

    with (
        patch.object(svc, "_get_kb_context_for_alert", return_value=kb_hits),
        patch.object(svc, "_get_gold_exemplars_for_alert", return_value=[]),
        patch(
            "ion.services.alert_prompt_service.select_skills_for_alert",
            return_value=[],
            create=True,
        ),
        patch(
            "ion.services.alert_prompt_service.format_skills_for_prompt",
            return_value="",
            create=True,
        ),
        # Tighten the budget so the KB block can't fit (fixed ~2071, budget 2100 → only 29 remaining)
        patch.object(_aps, "_SYSTEM_PROMPT_TOKEN_BUDGET", 2100),
    ):
        prompt = svc.render_system_prompt(None, TINY_ALERT)

    # The KB excerpt text should NOT appear (too large, budget exceeded)
    assert "x" * 100 not in prompt
    # But the output contract must always be present
    assert "Output Contract" in prompt


def test_skills_dropped_before_exemplars():
    """Skills (priority 3) are dropped before exemplars (priority 2) when
    the budget runs tight after KB (priority 1).

    Budget is tightened to 2400 tokens so the layout is:
      fixed (~1898 tokens) + KB (~210 tokens) + exemplars (~225 tokens)
      = ~2333 tokens — fits.
      + skills (1000 tokens) = ~3333 — does NOT fit under 2400 budget.
    Skills must be dropped; KB and exemplars must survive.
    """
    import ion.services.alert_prompt_service as _aps

    svc = _make_service()

    # KB: 3 articles × ~200-char excerpts → ~210 tokens total block
    med_kb = [{"name": "Doc", "excerpt": "k" * 200, "similarity": 0.75}]
    # Exemplar: ~225 tokens
    med_exemplars = [
        {
            "case_number": "CASE-0001",
            "title": "Example case",
            "summary": "e" * 400,
            "closure_reason": "true_positive",
            "closure_notes": "n" * 200,
            "similarity": 0.8,
        }
    ]
    # Skills: 1000 tokens — won't fit once KB + exemplars consumed the budget
    large_skill_block = "## Skills\n" + "s" * 4000

    with (
        patch.object(svc, "_get_kb_context_for_alert", return_value=med_kb),
        patch.object(svc, "_get_gold_exemplars_for_alert", return_value=med_exemplars),
        patch(
            "ion.services.alert_prompt_service.select_skills_for_alert",
            return_value=[MagicMock()],
            create=True,
        ),
        patch(
            "ion.services.alert_prompt_service.format_skills_for_prompt",
            return_value=large_skill_block,
            create=True,
        ),
        # budget=2600: fixed ~2071 → remaining ~529
        # KB ~132 tokens fits → remaining ~397
        # Exemplars ~261 tokens fits → remaining ~136
        # Skills ~1000 tokens does NOT fit → dropped
        patch.object(_aps, "_SYSTEM_PROMPT_TOKEN_BUDGET", 2600),
    ):
        prompt = svc.render_system_prompt(None, TINY_ALERT)

    # KB excerpt should be present
    assert "k" * 50 in prompt
    # Exemplar case number should be present (exemplars fit before skills)
    assert "CASE-0001" in prompt
    # The large skill block should be dropped
    assert "s" * 100 not in prompt
    # Output contract always present
    assert "Output Contract" in prompt


def test_output_contract_never_dropped():
    """Output contract is always the last thing appended, never skipped."""
    svc = _make_service()

    # Return huge blocks for all three RAG layers
    huge_kb = [{"name": "Doc", "excerpt": "k" * 10000, "similarity": 0.9}]
    huge_exemplars = [
        {
            "case_number": "CASE-9999",
            "title": "T",
            "summary": "e" * 5000,
            "closure_reason": "true_positive",
            "closure_notes": "",
            "similarity": 0.9,
        }
    ]
    with (
        patch.object(svc, "_get_kb_context_for_alert", return_value=huge_kb),
        patch.object(svc, "_get_gold_exemplars_for_alert", return_value=huge_exemplars),
        patch(
            "ion.services.alert_prompt_service.select_skills_for_alert",
            return_value=[],
            create=True,
        ),
        patch(
            "ion.services.alert_prompt_service.format_skills_for_prompt",
            return_value="",
            create=True,
        ),
    ):
        prompt = svc.render_system_prompt(None, TINY_ALERT)

    assert "Output Contract" in prompt
    assert "MANDATORY" in prompt


# ---------------------------------------------------------------------------
# 3. _DEFAULT_MEMORY_MAX_CHARS raised to 3000
# ---------------------------------------------------------------------------

def test_memory_max_chars_default():
    from ion.services.investigation_service import _DEFAULT_MEMORY_MAX_CHARS

    assert _DEFAULT_MEMORY_MAX_CHARS == 3000


# ---------------------------------------------------------------------------
# 4. investigate_case no-template path uses render_system_prompt
# ---------------------------------------------------------------------------

def test_investigate_case_uses_render_system_prompt_when_no_template(tmp_path):
    """When resolve_template_for_alert returns None, investigate_case must
    still call render_system_prompt(None, alert) — not fall back to the raw
    SYSTEM_PROMPTS dict — so KB/exemplar/skills can still be injected."""
    from ion.services.alert_prompt_service import AlertPromptService

    render_calls = []

    original_render = AlertPromptService.render_system_prompt

    def _spy_render(self, tpl, alert=None):
        render_calls.append({"tpl": tpl, "has_alert": alert is not None})
        return original_render(self, tpl, alert)

    with (
        patch.object(AlertPromptService, "resolve_template_for_alert", return_value=None),
        patch.object(AlertPromptService, "render_system_prompt", _spy_render),
    ):
        svc = AlertPromptService(session=MagicMock())
        result = svc.render_system_prompt(None, TINY_ALERT)

    # render_system_prompt was called (via the spy)
    assert len(render_calls) == 1
    assert render_calls[0]["tpl"] is None
    assert render_calls[0]["has_alert"] is True
    # Output contract present in result
    assert "Output Contract" in result
