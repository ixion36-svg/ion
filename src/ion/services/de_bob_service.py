"""Bob improvement loop — Phase 3 read side (feedback items + scorecard).

Computed-on-read from the deduped ``AIFeedback`` ledger (same MAX(id) per
``(alert_id, alert_prompt_template_id)`` contract as ``detection_health`` /
``de_metrics`` / ``bob_eval``). No new table, no background job.

- **Bob Feedback Items** — closures where Bob disagreed with the analyst,
  grouped into *classes* by ``(rule, bob_verdict → human_verdict)`` with counts,
  sample analyst reasons (``delta_reason``) and sample alert ids. These are the
  evidence a Bob-tuning proposal is drafted from.
- **Bob scorecard** — overall agreement rate, drift (recent vs older half), and
  the top disagreement classes. Plus a transparency disclosure of whether Bob's
  gold-exemplar retrieval self-adjusts from agreed cases (the one data-driven
  influence on Bob that isn't human-approved).
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ion.models.ai_feedback import AIFeedback
from ion.models.alert_triage import AlertTriage
from ion.services.ai_feedback_dedupe import (
    deduped_feedback_ids,
    is_scored,
)

_PENDING = "pending"
_UNMAPPED = "(unmapped)"


def _lookback() -> int:
    try:
        return int(os.environ.get("ION_DE_BOB_LOOKBACK_DAYS", "90"))
    except (TypeError, ValueError):
        return 90


def _pct(num: int, denom: int) -> Optional[float]:
    if denom <= 0:
        return None
    return round(num / denom * 100, 1)


def _deduped_rows(session: Session, cutoff: datetime):
    """Deduped ledger rows in-window, joined to the rule name."""
    deduped_ids = deduped_feedback_ids(cutoff)
    return session.execute(
        select(
            AIFeedback.agreement,
            AIFeedback.bob_suggested_verdict,
            AIFeedback.human_verdict,
            AIFeedback.auto_escalated,
            AIFeedback.created_at,
            AIFeedback.alert_id,
            AIFeedback.alert_prompt_template_id,
            AIFeedback.delta_reason,
            AlertTriage.rule_name,
        )
        .outerjoin(AlertTriage, AlertTriage.es_alert_id == AIFeedback.alert_id)
        .where(AIFeedback.id.in_(deduped_ids))
    ).all()


# Shared predicate — see ai_feedback_dedupe.is_scored.
_is_scored = is_scored


def get_bob_feedback(session: Session, days: Optional[int] = None) -> Dict[str, Any]:
    """Disagreement classes grouped by (rule, bob→human verdict)."""
    lookback = days if days is not None else _lookback()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(days=lookback)
    rows = _deduped_rows(session, cutoff)

    classes: Dict[tuple, Dict[str, Any]] = {}
    for (agreement, bob_v, human_v, auto_esc, created_at, alert_id,
         template_id, delta_reason, rule_name) in rows:
        if not _is_scored(bob_v, agreement, auto_esc) or agreement is not False:
            continue  # only scored disagreements
        rn = rule_name or _UNMAPPED
        key = (rn, bob_v, (human_v or "").lower())
        c = classes.get(key)
        if c is None:
            c = classes[key] = {
                "rule_name": rn,
                "bob_verdict": bob_v,
                "human_verdict": human_v,
                "template_id": template_id,
                "count": 0,
                "sample_reasons": [],
                "sample_alert_ids": [],
            }
        c["count"] += 1
        if delta_reason and delta_reason.strip() and len(c["sample_reasons"]) < 5:
            c["sample_reasons"].append(delta_reason.strip()[:300])
        if alert_id and len(c["sample_alert_ids"]) < 10:
            c["sample_alert_ids"].append(alert_id)

    items = sorted(classes.values(), key=lambda x: -x["count"])
    return {
        "period_days": lookback,
        "generated_at": now.isoformat(),
        "class_count": len(items),
        "total_disagreements": sum(x["count"] for x in items),
        "classes": items,
    }


def _few_shot_disclosure() -> Dict[str, Any]:
    """Transparency: is Bob's gold-exemplar retrieval self-adjusting from
    agreed cases? Data-driven RAG (not a prompt/model mutation), but the closest
    thing to unsupervised influence — surfaced so it is never silent."""
    on = os.environ.get("ION_FEW_SHOT_EXEMPLARS_ENABLED", "true").lower() in (
        "true", "1", "yes", "on")
    return {
        "gold_exemplar_retrieval_enabled": on,
        "note": (
            "When enabled, Bob's retrieval layer includes past cases the analyst "
            "closed in agreement with Bob. This is data-driven context, not a "
            "prompt-stack or model change, and is not human-approved per case — "
            "disable via ION_FEW_SHOT_EXEMPLARS_ENABLED=false if that governance "
            "is required."
        ),
    }


def get_bob_scorecard(session: Session, days: Optional[int] = None) -> Dict[str, Any]:
    """Agreement rate + drift (recent vs older half) + top disagreement classes."""
    lookback = days if days is not None else _lookback()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(days=lookback)
    midpoint = cutoff + (now - cutoff) / 2
    rows = _deduped_rows(session, cutoff)

    scored = agreed = 0
    r_scored = r_agreed = o_scored = o_agreed = 0
    for (agreement, bob_v, human_v, auto_esc, created_at, *_rest) in rows:
        if not _is_scored(bob_v, agreement, auto_esc):
            continue
        scored += 1
        is_recent = created_at is not None and created_at >= midpoint
        if agreement is True:
            agreed += 1
        if is_recent:
            r_scored += 1
            r_agreed += 1 if agreement is True else 0
        else:
            o_scored += 1
            o_agreed += 1 if agreement is True else 0

    recent_rate = _pct(r_agreed, r_scored)
    older_rate = _pct(o_agreed, o_scored)
    drift_delta = None
    direction = "flat"
    if recent_rate is not None and older_rate is not None:
        drift_delta = round(recent_rate - older_rate, 1)
        if drift_delta <= -5:
            direction = "declining"
        elif drift_delta >= 5:
            direction = "improving"

    fb = get_bob_feedback(session, days=lookback)
    return {
        "period_days": lookback,
        "generated_at": now.isoformat(),
        "summary": {
            "scored": scored,
            "agreed": agreed,
            "agreement_rate": _pct(agreed, scored),
            "drift": {
                "recent_rate": recent_rate,
                "older_rate": older_rate,
                "delta": drift_delta,
                "direction": direction,
            },
            "disagreement_classes": fb["class_count"],
            "total_disagreements": fb["total_disagreements"],
            "few_shot": _few_shot_disclosure(),
        },
        "top_classes": fb["classes"][:5],
    }
