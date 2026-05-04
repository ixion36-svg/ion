"""Records AIFeedback ledger rows when a case is closed.

Called from the case-close endpoint. Writes one row per alert in the case
that has both a suggested_verdict (from Bob) and a human closure_reason.
Agreement is computed as: `bob_suggested_verdict == human_verdict`.

Never raises — this is a metrics loop, not a correctness loop, so a failure
here must not block the case closure itself.
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def record_case_close_feedback(
    *,
    case,  # AlertCase
    human_verdict: str,
    human_closed_by_id: Optional[int],
    delta_reason: Optional[str],
    session: Session,
) -> int:
    """Write AIFeedback rows for every triage entry in the case.

    Returns count of rows written. Silent no-op on error.
    """
    try:
        from sqlalchemy import select

        from ion.models.ai_feedback import AIFeedback
        from ion.models.investigation import Investigation
    except Exception as exc:
        logger.debug("AIFeedback imports failed: %s", exc)
        return 0

    if not case or not human_verdict:
        return 0

    written = 0
    try:
        for triage in case.triage_entries or []:
            alert_id = triage.es_alert_id
            bob_verdict = triage.suggested_verdict
            bob_confidence = triage.suggested_verdict_confidence

            # Find the most recent Investigation for this alert, if any,
            # to link up investigation_id + template_id.
            inv = (
                session.execute(
                    select(Investigation)
                    .where(Investigation.alert_id_ref == alert_id)
                    .order_by(Investigation.id.desc())
                    .limit(1)
                ).scalar_one_or_none()
            )

            agreement: Optional[bool] = None
            if bob_verdict:
                agreement = (bob_verdict == human_verdict)

            fb = AIFeedback(
                investigation_id=inv.id if inv else None,
                case_id=case.id,
                alert_id=alert_id,
                alert_prompt_template_id=(
                    getattr(inv, "prompt_template_id", None) if inv else None
                ),
                bob_suggested_verdict=bob_verdict,
                bob_confidence=bob_confidence,
                human_verdict=human_verdict,
                human_closed_by_id=human_closed_by_id,
                agreement=agreement,
                delta_reason=delta_reason,
            )
            session.add(fb)
            written += 1
    except Exception as exc:
        logger.warning("AIFeedback capture failed for case %s: %s", getattr(case, "id", None), exc)
        return written

    return written
