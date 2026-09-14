"""Advisory grounding check for Bob's chat answers.

The chat surface retrieves reference context by substring match
(``ai_context_service`` runs ``ILIKE '%keyword%'``), so the block handed to the
model regularly contains near-misses rather than answers. A small model given
near-misses at conversational temperature will fill the gap with invented
specifics -- IOCs, CVEs, rule IDs -- that look like they came from the cited
source. This runs one cheap temp-0 pass afterwards that asks, against the
retrieved snippets only, which of the answer's specifics are not actually there.

It mirrors ``bob_verifier_service`` (the case-analysis verifier) in discipline
but not in shape: that one adjudicates a verdict against a deterministic
attack-path graph, this one adjudicates prose against retrieved text.

Governing rules:

* **Advisory only.** Never rewrites, blocks, or withholds the answer. The answer
  has already been streamed to the analyst by the time this runs; the result is
  appended as a separate SSE event.
* **Opt-in.** Gated on ``ION_CHAT_GROUNDING_CHECK``; off means not one extra
  token is spent.
* **Air-gap safe.** Ollama disabled, unreachable, or breaker-open degrades to a
  silent no-op. Never raises to the caller.
* **Nothing to verify is not a failure.** No reference context, or an answer too
  short to carry a claim, skips rather than reporting "ungrounded".

Result contract::

    # skipped (flag off / no context / air-gapped / unparseable):
    {"skipped": True, "grounded": None, "reason": str}
    # ran:
    {"skipped": False, "grounded": bool,
     "unsupported_claims": [str, ...], "notes": str}
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from ion.services.bob_verifier_service import parse_verifier_json

logger = logging.getLogger(__name__)

# Below this an answer is an acknowledgement or a clarifying question, not a
# claim worth spending a verifier pass on.
_MIN_ANSWER_CHARS = 200

# The verifier reads both texts in full; cap them so a long transcript can't
# push the pass past the context window and silently truncate the evidence.
_MAX_ANSWER_CHARS = 6000
_MAX_CONTEXT_CHARS = 12000

_GROUNDING_SYSTEM_PROMPT = (
    "You are ION's grounding checker. You are given REFERENCE CONTEXT that was "
    "retrieved for an analyst's question, and the ANSWER that was given. Your "
    "ONLY job is to list specifics asserted by the ANSWER that the REFERENCE "
    "CONTEXT does not support. A specific is a factual particular: an IOC, CVE "
    "id, MITRE technique id, hostname, file path, rule id, version, number, or "
    "a quotation attributed to a source. Treat the reference context as the only "
    "evidence: if the answer states a specific that does not appear there, it is "
    "unsupported. Do NOT flag general security knowledge, definitions, "
    "methodology, or advice that claims no source -- only specifics presented as "
    "fact. Do NOT answer the question yourself and do NOT rewrite the answer. "
    'Respond with a single JSON object and nothing else, of the form '
    '{"grounded": true|false, "unsupported_claims": ["..."], "notes": "..."}.'
)


def build_grounding_user_prompt(answer_text: str, context_block: str) -> str:
    """Assemble the two-part evidence prompt."""
    answer = (answer_text or "").strip()[:_MAX_ANSWER_CHARS]
    context = (context_block or "").strip()[:_MAX_CONTEXT_CHARS]
    return (
        "REFERENCE CONTEXT:\n"
        f"{context}\n\n"
        "ANSWER TO CHECK:\n"
        f"{answer}\n\n"
        "List only the specifics in the ANSWER that the REFERENCE CONTEXT does "
        "not support."
    )


def _skipped(reason: str) -> Dict[str, Any]:
    return {"skipped": True, "grounded": None, "reason": reason}


def _normalize_result(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce the parsed JSON into the stable grounding-result contract."""
    claims = obj.get("unsupported_claims")
    if not isinstance(claims, list):
        claims = []
    claims = [str(c).strip() for c in claims if str(c).strip()][:20]

    grounded = obj.get("grounded")
    if isinstance(grounded, str):
        grounded = grounded.strip().lower() in ("true", "yes", "grounded")
    if grounded is None:
        # A model that returns claims but omits the verdict still told us the
        # answer to the question we actually asked.
        grounded = not claims

    return {
        "skipped": False,
        "grounded": bool(grounded),
        "unsupported_claims": claims,
        "notes": str(obj.get("notes") or "").strip()[:500],
    }


def should_check(answer_text: Optional[str], context_block: Optional[str]) -> bool:
    """True when there is both an assertion to check and evidence to check it against."""
    if not context_block or not context_block.strip():
        return False
    return len((answer_text or "").strip()) >= _MIN_ANSWER_CHARS


async def verify_chat_answer(
    answer_text: str,
    context_block: str,
    *,
    user_id: int = 0,
    ollama: Any = None,
) -> Dict[str, Any]:
    """Run the grounding check (one cheap temp-0 JSON LLM call).

    Flag-gated and air-gap safe. Returns the stable grounding-result contract
    (see module docstring). NEVER raises to the caller and NEVER mutates state.
    """
    try:
        from ion.core.config import get_config

        if not getattr(get_config(), "chat_grounding_check", False):
            return _skipped("disabled")
    except Exception:
        logger.debug("grounding: config unavailable", exc_info=True)
        return _skipped("disabled")

    if not should_check(answer_text, context_block):
        return _skipped("nothing-to-check")

    try:
        if ollama is None:
            from ion.services.ollama_service import get_ollama_service

            ollama = get_ollama_service()
        if not getattr(ollama, "enabled", True):
            return _skipped("ollama-disabled")
    except Exception:
        logger.debug("grounding: ollama resolution failed", exc_info=True)
        return _skipped("ollama-unavailable")

    try:
        result = await ollama.chat(
            messages=[
                {
                    "role": "user",
                    "content": build_grounding_user_prompt(answer_text, context_block),
                }
            ],
            system_prompt=_GROUNDING_SYSTEM_PROMPT,
            context_type="chat_grounding",
            user_id=user_id,
            temperature=0.0,
            response_format="json",
        )
    except Exception:
        # Breaker open, connect error, timeout. The answer is already with the
        # analyst; the check is purely advisory.
        logger.debug("grounding: LLM call failed — treating as no-op", exc_info=True)
        return _skipped("ollama-unavailable")

    parsed = parse_verifier_json((result or {}).get("content") or "")
    if parsed is None:
        logger.debug("grounding: unparseable JSON reply — treating as no-op")
        return _skipped("unparseable")
    return _normalize_result(parsed)


def render_grounding_note(result: Dict[str, Any]) -> str:
    """One-line advisory summary. Empty string when the check was skipped."""
    if not result or result.get("skipped"):
        return ""
    claims: List[str] = result.get("unsupported_claims") or []
    if result.get("grounded") and not claims:
        return "Every specific in this answer appears in the cited sources."
    if not claims:
        return "Some of this answer is not supported by the cited sources."
    head = "; ".join(claims[:3])
    more = f" (+{len(claims) - 3} more)" if len(claims) > 3 else ""
    return f"Not found in the cited sources: {head}{more}"
