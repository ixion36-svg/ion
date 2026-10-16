"""Alert prompt templates and their 30-day scorecards."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_any_permission
from ion.storage.database import get_db_session
from ion.web.alert_prompt_api import get_all_scorecards, list_alert_prompts
from ion.web.ui._shared import plain, templates

logger = logging.getLogger(__name__)
router = APIRouter()


def scorecard_summary(scorecards: dict) -> dict:
    cards = list(scorecards.values())
    samples = [c.get("sample_size") for c in cards]
    evaluated = [c.get("evaluated") for c in cards]
    tuning = [c.get("tuning_needed") for c in cards]
    agreement = None
    if all(n is not None for n in evaluated):
        denominator = sum(evaluated)
        measured = [c for c in cards if c.get("evaluated") > 0]
        if denominator > 0 and all(c.get("agreement_pct") is not None for c in measured):
            # Recover integer agreements using the API's evaluated denominator,
            # never its sample count, which includes abstentions.
            agreed = sum(int(c["evaluated"] * c["agreement_pct"] / 100 + 0.5) for c in measured)
            agreement = int(100 * agreed / denominator + 0.5)
    return {
        "templates": len(cards),
        "samples": sum(samples) if all(n is not None for n in samples) else None,
        "agreement": agreement,
        "tuning": sum(v is True for v in tuning) if all(type(v) is bool for v in tuning) else None,
    }


@router.get(
    "/alert-prompts",
    response_class=HTMLResponse,
    dependencies=[Depends(require_any_permission(["playbook:read"]))],
)
def alert_prompt_templates_fragment(
    request: Request,
    enabled_only: bool = False,
    session: Session = Depends(get_db_session),
) -> HTMLResponse:
    items = None
    scorecards = None
    summary = None
    failed = False
    scores_failed = False
    try:
        # Reuse the JSON readers directly because their payload logic is inline
        # and this conversion owns no API files.
        items = list_alert_prompts(enabled_only=enabled_only, session=session)["templates"]
        items = [dict(item, severity_hint=plain(item.get("severity_hint"))) for item in items]
    except Exception:
        logger.exception("Alert prompt templates could not be read")
        failed = True
    try:
        scorecards = get_all_scorecards(window_days=30, session=session)["scorecards"]
        summary = scorecard_summary(scorecards)
    except Exception:
        logger.exception("Alert prompt scorecards could not be read")
        scores_failed = True
    return templates.TemplateResponse(
        request=request,
        name="_fragments/alert_prompt_templates.html",
        context={"items": items, "scorecards": scorecards, "summary": summary,
                 "failed": failed, "scores_failed": scores_failed},
    )
