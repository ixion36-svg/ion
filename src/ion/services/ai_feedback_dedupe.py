"""The one AIFeedback dedupe contract (route audit phase 5).

The `ai_feedback` ledger is dual-written: once when Bob fires (often a
circuit-breaker "pending" row) and again when the case closes. **Every reader
must therefore keep only `MAX(id)` per `(alert_id, alert_prompt_template_id)`
inside the window**, or a single alert is counted twice and every derived rate
is wrong. `models/ai_feedback.py` carries an index specifically for this
GROUP BY.

Before this module the contract was restated in four hand-maintained copies —
`detection_health_service`, `de_bob_service`, `alert_prompt_api` and
`bob_eval_service` — each with a docstring insisting it stay identical to the
others. **One had already drifted:** the `/ai-scorecard` reader counted any row
with a non-null `agreement`, including `auto_escalated` circuit-breaker
abstentions, so its denominator was larger than every other surface's and its
agreement rate correspondingly different.

This module owns the contract. Callers still choose their own columns and joins;
what they share is *which rows count* and *what "scored" means*.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import func, select

from ion.models.ai_feedback import AIFeedback


def deduped_feedback_ids(
    cutoff: Optional[datetime] = None,
    *,
    require_template: bool = False,
):
    """Subquery yielding one ledger id per (alert_id, template_id).

    Args:
        cutoff: only rows with ``created_at >= cutoff`` participate. Pass
            ``None`` to dedupe across **all** time — which is what you want when
            the caller filters the window *after* deduping, so that a row
            resolved outside the window still supersedes its earlier pending
            sentinel (the wallboard reads it this way).
        require_template: restrict to rows carrying an
            ``alert_prompt_template_id``. Per-template readers (scorecards, eval
            runs) need this; per-rule and global readers do not.

    Use as ``.where(AIFeedback.id.in_(deduped_feedback_ids(cutoff)))``.

    Note: `storage/investigation_memory_repository` deliberately keeps its own
    variant — it groups the same way but scopes by `alert_signature` through a
    join to `Investigation` and drops `human_verdict == "pending"`, so it is a
    different question, not a copy of this one.
    """
    stmt = select(func.max(AIFeedback.id))
    if cutoff is not None:
        stmt = stmt.where(AIFeedback.created_at >= cutoff)
    if require_template:
        stmt = stmt.where(AIFeedback.alert_prompt_template_id.isnot(None))
    return stmt.group_by(AIFeedback.alert_id, AIFeedback.alert_prompt_template_id)


def is_scored(
    bob_verdict: Any,
    agreement: Optional[bool],
    auto_escalated: Optional[bool],
) -> bool:
    """True when Bob made a real, scored suggestion on this row.

    Excludes:
    - rows where Bob never suggested anything (``bob_verdict`` falsy),
    - rows never adjudicated by a human (``agreement is None``),
    - **circuit-breaker abstentions** (``auto_escalated``) — Bob deliberately
      declined to call it, so counting it as a disagreement punishes the very
      behaviour the breaker exists to produce.

    That last exclusion is the one `/ai-scorecard` was missing.
    """
    return bool(bob_verdict) and agreement is not None and not auto_escalated


def pct(numerator: int, denominator: int) -> Optional[float]:
    """Percentage rounded to 1dp, or None when there is nothing to divide."""
    if not denominator:
        return None
    return round((numerator / denominator) * 100, 1)
