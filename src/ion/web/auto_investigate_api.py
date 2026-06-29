"""Bob Auto-Investigate endpoints (v0.46.0).

On-demand agentic investigation for a single alert or a whole case. Gathers an
evidence ledger from ION's own data, runs ONE bounded LLM synthesis call, and
returns a structured, CITED report (verdict + findings + recommended playbook)
whose citations have been validated server-side against the real ledger.

Mirrors ``bob_analysis_api``: read-permission-gated, 503-graceful when Ollama
is unavailable, and does NOT persist — the analyst reviews the report and may
save it as a note / apply the suggested verdict through the existing endpoints.

Permissions: alert path ``alert:read``; case path ``case:read``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ion.auth.dependencies import require_permission
from ion.models.alert_triage import AlertCase
from ion.models.user import User
from ion.services.auto_investigation_service import (
    AutoInvestigationService,
    EvidenceBundle,
)
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auto-investigate"])


class AutoInvestigateResponse(BaseModel):
    report: Dict[str, Any]
    subject: Dict[str, Any]
    evidence: List[Dict[str, Any]]
    model: Optional[str] = None
    counts: Dict[str, int]
    generated_at: str


def _serialise_evidence(bundle: EvidenceBundle) -> List[Dict[str, Any]]:
    return [
        {"id": it.id, "kind": it.kind, "title": it.title, "detail": it.detail}
        for it in bundle.items
    ]


async def _synthesise(bundle: EvidenceBundle, user_id: int) -> AutoInvestigateResponse:
    """Run the single LLM synthesis call over a gathered bundle and finalise."""
    svc = AutoInvestigationService()
    system_prompt, user_prompt = svc.build_prompts(bundle)

    try:
        from ion.services.ollama_service import get_ollama_service

        ollama = get_ollama_service()
        if not getattr(ollama, "enabled", True):
            raise HTTPException(
                status_code=503,
                detail="Ollama is disabled — Auto-Investigate unavailable",
            )
        result = await ollama.chat(
            messages=[{"role": "user", "content": user_prompt}],
            system_prompt=system_prompt,
            context_type="auto_investigate",
            user_id=user_id,
            temperature=0.2,
            response_format="json",
            max_tokens=4096,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("Auto-Investigate Ollama call failed")
        raise HTTPException(status_code=503, detail=f"LLM call failed: {exc}")

    content = (result or {}).get("content") or ""
    if not content.strip():
        raise HTTPException(
            status_code=503,
            detail="Bob returned an empty response — please retry.",
        )

    report = svc.parse_and_validate(content, bundle)
    return AutoInvestigateResponse(
        report=report,
        subject={
            "kind": bundle.subject_kind,
            "id": bundle.subject_id,
            "title": bundle.subject_title,
            "fields": bundle.subject_fields,
        },
        evidence=_serialise_evidence(bundle),
        model=(result or {}).get("model"),
        counts=bundle.counts,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


@router.post(
    "/elasticsearch/alerts/{alert_id}/auto-investigate",
    response_model=AutoInvestigateResponse,
)
async def auto_investigate_alert(
    alert_id: str,
    user: User = Depends(require_permission("alert:read")),
    session: Session = Depends(get_db_session),
) -> AutoInvestigateResponse:
    """Run an agentic auto-investigation for a single ES alert."""
    svc = AutoInvestigationService()
    bundle = await svc.gather_for_alert(session, alert_id)
    if bundle is None:
        # No ES doc and no triage row — still attempt a (sparse) investigation
        # so the analyst gets a response rather than a 404 oracle.
        bundle = EvidenceBundle(
            subject_kind="alert", subject_id=str(alert_id), subject_title=str(alert_id),
        )
        bundle.playbook_candidates = svc._gather_playbook_candidates(session)
    return await _synthesise(bundle, user.id)


@router.post(
    "/elasticsearch/alerts/cases/{case_id}/auto-investigate",
    response_model=AutoInvestigateResponse,
)
async def auto_investigate_case(
    case_id: int,
    user: User = Depends(require_permission("case:read")),
    session: Session = Depends(get_db_session),
) -> AutoInvestigateResponse:
    """Run an agentic auto-investigation for a whole case."""
    case = session.query(AlertCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    svc = AutoInvestigationService()
    bundle = svc.gather_for_case_sync(session, case)
    return await _synthesise(bundle, user.id)
