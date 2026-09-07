"""Verdict Review — surface + resolve Bob's pending per-alert verdicts.

Bob writes an ``AIFeedback`` row with ``human_verdict="pending"`` at
investigation fire-time (``investigation_service``). Those rows accumulate with
no review surface; this service lists the latest-still-pending row per alert and
lets a human resolve one (accept Bob's verdict or override), stamping the ledger
(agreement computed) so it counts in the eval / scorecard readers.
"""

import logging
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ion.models.ai_feedback import AIFeedback
from ion.models.alert_triage import AlertTriage
from ion.services.ai_feedback_dedupe import deduped_feedback_ids

logger = logging.getLogger(__name__)

# The output contract Bob's verdicts (and a human's) are drawn from.
_VALID_VERDICTS = {"true_positive", "false_positive", "benign_true_positive", "inconclusive"}


def _row_to_dict(r: AIFeedback, triage: Optional[AlertTriage]) -> dict:
    return {
        "id": r.id,
        "alert_id": r.alert_id,
        "investigation_id": r.investigation_id,
        "rule_name": triage.rule_name if triage else None,
        "priority": triage.priority if triage else None,
        "bob_verdict": r.bob_suggested_verdict,
        "bob_confidence": r.bob_confidence,
        "bob_confidence_int": r.bob_confidence_int,
        "auto_escalated": r.auto_escalated,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def list_pending_verdicts(session: Session, limit: int = 100) -> list[dict]:
    """Latest still-pending Bob verdict per alert, with alert context.

    Uses the canonical dedup (``MAX(id)`` per ``(alert_id, template_id)``) so a
    pending row already superseded by a later resolved row for the same alert is
    excluded — the queue only shows what is genuinely awaiting a decision.
    """
    latest = deduped_feedback_ids()
    rows = (
        session.execute(
            select(AIFeedback)
            .where(AIFeedback.id.in_(latest), AIFeedback.human_verdict == "pending")
            .order_by(AIFeedback.id.desc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    out = []
    for r in rows:
        triage = (
            session.query(AlertTriage).filter_by(es_alert_id=r.alert_id).first()
            if r.alert_id
            else None
        )
        out.append(_row_to_dict(r, triage))
    return out


def resolve_verdict(
    session: Session,
    feedback_id: int,
    human_verdict: str,
    reviewer_id: int,
    delta_reason: Optional[str] = None,
) -> dict:
    """Resolve one pending verdict: stamp the human decision + agreement.

    The ownership/state check runs here, inside the service, before the mutation
    (ION's TOCTOU-safe pattern): a non-pending row is refused rather than
    silently re-stamped.
    """
    if human_verdict not in _VALID_VERDICTS:
        return {"error": f"Invalid verdict '{human_verdict}'", "status": "error"}
    fb = session.get(AIFeedback, feedback_id)
    if fb is None:
        return {"error": "Verdict not found", "status": "error"}
    if fb.human_verdict != "pending":
        return {"error": f"Already resolved ({fb.human_verdict})", "status": "error"}

    fb.human_verdict = human_verdict
    fb.human_closed_by_id = reviewer_id
    # agreement only means something when Bob actually suggested a verdict.
    fb.agreement = (
        (fb.bob_suggested_verdict == human_verdict) if fb.bob_suggested_verdict else None
    )
    if delta_reason:
        fb.delta_reason = delta_reason
    session.commit()
    logger.info(
        "Verdict %d resolved by user %d: %s (agreement=%s)",
        feedback_id, reviewer_id, human_verdict, fb.agreement,
    )
    return {
        "id": fb.id,
        "human_verdict": human_verdict,
        "agreement": fb.agreement,
        "status": "resolved",
    }


def verdict_metrics(session: Session) -> dict:
    """Queue depth + agreement rate over resolved, Bob-scored rows."""
    pending = (
        session.execute(
            select(func.count())
            .select_from(AIFeedback)
            .where(AIFeedback.id.in_(deduped_feedback_ids()), AIFeedback.human_verdict == "pending")
        ).scalar()
        or 0
    )
    scored = (
        session.execute(select(AIFeedback.agreement).where(AIFeedback.agreement.isnot(None)))
        .scalars()
        .all()
    )
    reviewed = len(scored)
    agree = sum(1 for a in scored if a)
    return {
        "pending": pending,
        "reviewed": reviewed,
        "agreement_rate": round(agree / reviewed, 3) if reviewed else None,
    }
