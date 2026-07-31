"""Adversarial verifier pass for Bob's case analysis (Attack Path Phase 3).

The "validation layer": before a Bob case-analysis verdict is surfaced, run a
single cheap adversarial LLM check that asks whether the *cited* deterministic
attack path actually supports the stated verdict and severity — and flags any
claim that references a node / edge / alert NOT present in the graph. This
extends ION's existing anti-hallucination discipline
(``auto_investigation_service.parse_and_validate`` citation-drop + the
``investigation_service`` confidence circuit-breaker) to the on-demand
case-analysis surface.

Governing rules (mirror the whole feature):

* **Advisory only.** The verifier NEVER mutates stored alert / case state. It
  flags and *recommends* a downgrade; the human decides.
* **Fork E — trigger.** Only medium-confidence *decisive* verdicts are verified
  (high-confidence and abstentions are skipped — cheap by construction).
* **Air-gap safe.** If Ollama is disabled / unreachable, or the path is empty,
  the verifier is a silent no-op: it returns ``{"supported": None,
  "skipped": True, ...}`` and never blocks or fails the analysis.

Result schema (returned by :func:`verify_analysis`)::

    # skipped (gated out / air-gapped / degraded):
    {"skipped": True, "supported": None, "reason": str}
    # ran:
    {"skipped": False, "supported": bool,
     "unsupported_claims": [str, ...],
     "recommended_band": str|None, "notes": str}
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Decisive verdicts (an abstention like ``inconclusive`` / ``None`` is NOT
# verified — nothing to adversarially downgrade).
_DECISIVE_VERDICTS = frozenset(
    {"true_positive", "false_positive", "benign_true_positive"}
)

# Verdict tokens the case-analysis persona emits, longest-first so
# ``benign_true_positive`` wins over the ``true_positive`` substring.
_VERDICT_TOKENS = (
    "benign_true_positive",
    "true_positive",
    "false_positive",
    "inconclusive",
)


def extract_verdict(analysis_text: Optional[str]) -> Optional[str]:
    """Best-effort verdict token from Bob's markdown analysis.

    Matches the snake_case tokens the persona defines (and their spaced/hyphen
    variants). Returns the canonical snake_case token, or ``None``.
    """
    if not analysis_text:
        return None
    text = analysis_text.lower()
    for token in _VERDICT_TOKENS:
        # tolerate space / hyphen separators between the words
        pat = token.replace("_", r"[ _\-]")
        if re.search(rf"\b{pat}\b", text):
            return token
    return None


def extract_confidence_band(analysis_text: Optional[str]) -> Optional[str]:
    """Best-effort confidence band (high|medium|low) from Bob's markdown.

    Looks for a stated confidence near the word "confidence" (either order).
    Returns ``None`` when no confidence is stated — the caller then skips the
    verifier (Fork E: only *medium* confidence is verified).
    """
    if not analysis_text:
        return None
    text = analysis_text.lower()
    m = re.search(r"confidence[^\n]{0,40}?\b(high|medium|low)\b", text)
    if m:
        return m.group(1)
    m = re.search(r"\b(high|medium|low)\b[^\n]{0,20}?confidence", text)
    if m:
        return m.group(1)
    return None


def should_verify(confidence_band: Optional[str], verdict: Optional[str]) -> bool:
    """Fork E gate: verify only medium-confidence, decisive verdicts.

    Pure + deterministic. High/low confidence and abstentions return ``False``
    so the (cheap) verifier never runs on cases where it adds no value.
    """
    band = (confidence_band or "").strip().lower()
    v = (verdict or "").strip().lower()
    return band == "medium" and v in _DECISIVE_VERDICTS


# ── Prompt builder (pure — tested without the LLM) ───────────────────────────

_VERIFIER_SYSTEM_PROMPT = (
    "You are ION's adversarial verifier. Another analyst (Bob) has produced a "
    "case verdict; a deterministic attack-path graph for the case is provided. "
    "Your ONLY job is to check, skeptically, whether that graph actually "
    "supports the stated verdict and severity. Assume the verdict may be wrong. "
    "Treat the attack-path graph as ground truth: any claim in the analysis "
    "that references a node id, edge, or alert_id NOT present in the graph is an "
    "unsupported claim. If the verdict or its severity is not supported by the "
    "graph, recommend a lower reachability/severity band. Do NOT invent new "
    "findings, do NOT re-analyze the case, and do NOT rewrite the verdict — only "
    "adjudicate support. Respond with a single JSON object and nothing else."
)


def build_verifier_user_prompt(
    analysis_text: str,
    verdict: Optional[str],
    confidence_band: Optional[str],
    path_dict: Optional[Dict[str, Any]],
) -> str:
    """Render the adversarial verifier user prompt (pure, deterministic).

    Reuses the same compact structured attack-path rendering Bob reasoned over
    (``_build_attack_path_prompt_block``) so the verifier checks the analysis
    against the *identical* graph. No I/O, no LLM.
    """
    # Lazy import: the renderer is a pure string builder living in the web layer;
    # importing it lazily avoids a service→web import at module load.
    try:
        from ion.web.bob_analysis_api import _build_attack_path_prompt_block
        path_block = _build_attack_path_prompt_block(path_dict) or "_No attack-path graph available._"
    except Exception:  # pragma: no cover - defensive
        path_block = "_No attack-path graph available._"

    parts: List[str] = [
        "## Verdict under review",
        f"- Verdict: `{verdict or 'unknown'}`",
        f"- Stated confidence: `{confidence_band or 'unknown'}`",
        "",
        "## Analyst's analysis (verbatim)",
        (analysis_text or "").strip() or "_(empty)_",
        "",
        path_block.strip(),
        "",
        "## Your adjudication",
        "Adversarially check the analysis against the attack path above:",
        "- Does the cited attack path support this verdict AND its severity?",
        "- List every claim in the analysis that references a node id, edge, or "
        "alert_id that is NOT present in the graph above.",
        "- If the verdict/severity is unsupported, recommend a downgrade "
        "(a lower reachability band).",
        "",
        "Respond with ONLY this JSON object (no prose, no code fence):",
        '{"supported": <true|false>, "unsupported_claims": ["<claim>", ...], '
        '"recommended_band": "<critical|high|medium|low|null>", '
        '"notes": "<one-sentence justification>"}',
    ]
    return "\n".join(parts)


# ── JSON parse ───────────────────────────────────────────────────────────────


def _parse_verifier_json(content: str) -> Optional[Dict[str, Any]]:
    """Parse the verifier's JSON reply, tolerating a stray code fence / prose."""
    if not content:
        return None
    txt = content.strip()
    # Strip a leading/trailing markdown fence if present.
    if txt.startswith("```"):
        txt = re.sub(r"^```[a-zA-Z]*\n?", "", txt)
        txt = re.sub(r"\n?```$", "", txt).strip()
    try:
        obj = json.loads(txt)
    except Exception:
        # Fall back to the first {...} span.
        m = re.search(r"\{.*\}", txt, re.DOTALL)
        if not m:
            return None
        try:
            obj = json.loads(m.group(0))
        except Exception:
            return None
    return obj if isinstance(obj, dict) else None


def _normalize_result(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce the parsed JSON into the stable verifier-result contract."""
    supported = obj.get("supported")
    if isinstance(supported, str):
        supported = supported.strip().lower() in ("true", "yes", "supported")
    claims = obj.get("unsupported_claims")
    if not isinstance(claims, list):
        claims = []
    claims = [str(c).strip() for c in claims if str(c).strip()][:20]
    band = obj.get("recommended_band")
    if band is not None:
        band = str(band).strip().lower() or None
        if band in ("null", "none"):
            band = None
    notes = str(obj.get("notes") or "").strip()[:500]
    return {
        "skipped": False,
        "supported": bool(supported) if supported is not None else None,
        "unsupported_claims": claims,
        "recommended_band": band,
        "notes": notes,
    }


# ── Async runner ─────────────────────────────────────────────────────────────


def _skipped(reason: str) -> Dict[str, Any]:
    return {"skipped": True, "supported": None, "reason": reason}


async def verify_analysis(
    analysis_text: str,
    verdict: Optional[str],
    confidence_band: Optional[str],
    path_dict: Optional[Dict[str, Any]],
    *,
    user_id: int = 0,
    ollama: Any = None,
) -> Dict[str, Any]:
    """Run the adversarial verifier (one cheap temp-0 JSON LLM call).

    Fork-E gated and air-gap safe. Returns the stable verifier-result contract
    (see module docstring). NEVER raises to the caller and NEVER mutates state.
    """
    # Fork E — only medium-confidence, decisive verdicts.
    if not should_verify(confidence_band, verdict):
        return _skipped("not-medium-decisive")

    # Nothing to verify against.
    if not path_dict or not (path_dict.get("nodes") or []):
        return _skipped("no-attack-path")

    # Air-gap: resolve + gate on Ollama; any unavailability → silent no-op.
    try:
        if ollama is None:
            from ion.services.ollama_service import get_ollama_service
            ollama = get_ollama_service()
        if not getattr(ollama, "enabled", True):
            return _skipped("ollama-disabled")
    except Exception:
        logger.debug("verifier: ollama resolution failed", exc_info=True)
        return _skipped("ollama-unavailable")

    system_prompt = _VERIFIER_SYSTEM_PROMPT
    user_prompt = build_verifier_user_prompt(
        analysis_text, verdict, confidence_band, path_dict
    )

    try:
        result = await ollama.chat(
            messages=[{"role": "user", "content": user_prompt}],
            system_prompt=system_prompt,
            context_type="case_verification",
            user_id=user_id,
            temperature=0.0,
            response_format="json",
        )
    except Exception:
        # Circuit breaker open, connect error, timeout, etc. — never fail the
        # analysis; the verifier is purely advisory.
        logger.debug("verifier: LLM call failed — treating as no-op", exc_info=True)
        return _skipped("ollama-unavailable")

    parsed = _parse_verifier_json((result or {}).get("content") or "")
    if parsed is None:
        logger.debug("verifier: unparseable JSON reply — treating as no-op")
        return _skipped("unparseable")
    return _normalize_result(parsed)


# ── Rendering the advisory Verification block ────────────────────────────────


def render_verification_block(result: Dict[str, Any]) -> str:
    """Markdown for the advisory Verification block appended to the analysis.

    Returns ``""`` when the verifier was skipped (silent no-op).
    """
    if not result or result.get("skipped"):
        return ""
    supported = result.get("supported")
    lines: List[str] = [
        "---",
        "## Verification (advisory)",
        "_An adversarial pass checked this verdict against the deterministic "
        "attack path. Advisory only — it does not change the verdict._",
    ]
    if supported is True:
        lines.append("- **Supported by the attack path:** yes")
    elif supported is False:
        lines.append("- **Supported by the attack path:** NO — consider a downgrade")
    else:
        lines.append("- **Supported by the attack path:** undetermined")
    claims = result.get("unsupported_claims") or []
    if claims:
        lines.append("- **Claims not grounded in the graph:**")
        for c in claims[:10]:
            lines.append(f"  - {c}")
    band = result.get("recommended_band")
    if band:
        lines.append(f"- **Recommended reachability band:** {band}")
    notes = (result.get("notes") or "").strip()
    if notes:
        lines.append(f"- **Verifier notes:** {notes}")
    return "\n".join(lines)
