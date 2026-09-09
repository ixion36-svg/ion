"""Bob custom investigation templates API (ION_BOB_CUSTOM_TEMPLATES).

Read the custom template for a rule, generate one for an alert's rule (one bounded
LLM call over the rule description + authored guide + gathered evidence), and
review it (approve / reject). Mirrors auto_investigate_api: read-gated,
503-graceful when Ollama is down, human-in-the-loop before a custom guide is
trusted.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.core.config import get_config
from ion.models.rule_investigation_template import STATUS_APPROVED, STATUS_REJECTED
from ion.models.user import User
from ion.services.auto_investigation_service import AutoInvestigationService
from ion.services.rule_template_service import (
    build_generation_prompt,
    compute_source_hash,
    get_template,
    list_pending,
    rule_fields_from_raw,
    set_status,
    upsert_generated,
)
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)
router = APIRouter(tags=["rule-investigation-template"])


@router.get("/alerts/investigation-template")
def get_rule_template(
    rule_id: str = Query("", max_length=512),
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    """The custom template for a rule (or null), plus whether generation is on."""
    row = get_template(session, rule_id)
    return {
        "template": row.to_dict() if row else None,
        "generation_enabled": get_config().bob_custom_templates,
    }


@router.get("/alerts/investigation-template/pending")
def list_pending_templates(
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    """Templates awaiting review — the review queue's data source."""
    return {"pending": [r.to_dict() for r in list_pending(session)]}


@router.post("/elasticsearch/alerts/{alert_id}/investigation-template/generate")
async def generate_rule_template(
    alert_id: str,
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    """Generate (or regenerate) a custom investigation template for this alert's
    rule, from the rule description + authored guide + gathered evidence. Writes a
    pending_review row for human review."""
    if not get_config().bob_custom_templates:
        raise HTTPException(status_code=403, detail="Bob custom templates are disabled")

    svc = AutoInvestigationService()
    bundle = await svc.gather_for_alert(session, alert_id)
    raw = await svc._fetch_alert_raw(alert_id) or {}
    rf = rule_fields_from_raw(raw)
    rule_name = rf["rule_name"] or (bundle.subject_title if bundle else "") or str(alert_id)
    rule_id = rule_name.strip()
    if not rule_id:
        raise HTTPException(status_code=422, detail="Alert has no identifiable rule")

    evidence_text = bundle.render_ledger() if bundle else ""
    evidence_ids = sorted(bundle.evidence_ids) if bundle else []
    system_prompt, user_prompt = build_generation_prompt(
        rule_name, rf["rule_description"], rf["authored_guide"], evidence_text
    )

    try:
        from ion.services.ollama_service import get_ollama_service

        ollama = get_ollama_service()
        if not getattr(ollama, "enabled", True):
            raise HTTPException(status_code=503, detail="Ollama is disabled — generation unavailable")
        result = await ollama.chat(
            messages=[{"role": "user", "content": user_prompt}],
            system_prompt=system_prompt,
            context_type="rule_template",
            user_id=user.id,
            temperature=0.2,
            max_tokens=1024,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("Rule-template generation Ollama call failed")
        raise HTTPException(status_code=503, detail=f"LLM call failed: {exc}")

    checklist = ((result or {}).get("content") or "").strip()
    if not checklist:
        raise HTTPException(status_code=503, detail="Bob returned an empty template — please retry.")

    row = upsert_generated(
        session,
        rule_id=rule_id,
        rule_name=rule_name,
        checklist_text=checklist,
        model=(result or {}).get("model"),
        source_hash=compute_source_hash(rf["rule_description"], rf["authored_guide"], evidence_ids),
        evidence_ids=evidence_ids,
    )
    return {"template": row.to_dict()}


def _review(template_id: int, status: str, user: User, session: Session) -> Dict[str, Any]:
    row = set_status(session, template_id, status, user.id)
    if row is None:
        raise HTTPException(status_code=404, detail="Template not found")
    return {"template": row.to_dict()}


@router.post("/alerts/investigation-template/{template_id}/approve")
def approve_rule_template(
    template_id: int,
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    return _review(template_id, STATUS_APPROVED, user, session)


@router.post("/alerts/investigation-template/{template_id}/reject")
def reject_rule_template(
    template_id: int,
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
) -> Dict[str, Any]:
    return _review(template_id, STATUS_REJECTED, user, session)
