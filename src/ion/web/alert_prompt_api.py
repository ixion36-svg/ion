"""Alert Prompt Templates API — per-rule LLM investigation prompts."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import (
    get_current_user,
    require_any_permission,
    require_page_auth,
)
from ion.models.user import User
from ion.services.alert_prompt_service import AlertPromptService
from ion.storage.alert_prompt_repository import AlertPromptRepository
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["alert-prompts"])

# Templates dir — resolve relative to this file so we share server.py's dir.
# We also mirror the ion_version global that server.py sets so {{ ion_version }}
# in base.html renders correctly.
_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
try:
    import ion as _ion_pkg
    _templates.env.globals["ion_version"] = _ion_pkg.__version__
except Exception:  # pragma: no cover — defensive: never block startup on this
    _templates.env.globals.setdefault("ion_version", "")

# Permission fallback: the spec asks for "playbooks:manage" but the ION
# permission inventory uses per-verb names. Fall back to playbook:create OR
# playbook:update for write ops, playbook:read for reads.
_MANAGE_PERMS = ["playbook:create", "playbook:update", "playbook:delete"]
_READ_PERMS = ["playbook:read"]


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class AlertPromptCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    prompt_text: str = Field(..., min_length=1)
    description: Optional[str] = None
    enabled: bool = True
    rule_ids: Optional[List[str]] = None
    rule_groups: Optional[List[str]] = None
    rule_id_pattern: Optional[str] = None
    mitre_techniques: Optional[List[str]] = None
    mitre_tactics: Optional[List[str]] = None
    priority: int = 100
    investigation_checklist_text: Optional[str] = None
    severity_hint: Optional[str] = None
    expected_outputs: Optional[List[str]] = None
    # v0.21.0: per-template circuit-breaker threshold (0-100, NULL = use global)
    confidence_threshold_override: Optional[int] = Field(
        default=None, ge=0, le=100
    )


class AlertPromptUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=255)
    prompt_text: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    rule_ids: Optional[List[str]] = None
    rule_groups: Optional[List[str]] = None
    rule_id_pattern: Optional[str] = None
    mitre_techniques: Optional[List[str]] = None
    mitre_tactics: Optional[List[str]] = None
    priority: Optional[int] = None
    investigation_checklist_text: Optional[str] = None
    severity_hint: Optional[str] = None
    expected_outputs: Optional[List[str]] = None
    # v0.21.0: per-template circuit-breaker threshold (0-100, NULL = use global)
    confidence_threshold_override: Optional[int] = Field(
        default=None, ge=0, le=100
    )


class ResolveRequest(BaseModel):
    alert: dict


# ---------------------------------------------------------------------------
# JSON API endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/api/alert-prompts",
    dependencies=[Depends(require_any_permission(_READ_PERMS))],
)
def list_alert_prompts(
    enabled_only: bool = False,
    session: Session = Depends(get_db_session),
):
    repo = AlertPromptRepository(session)
    items = repo.list_all(enabled_only=enabled_only)
    return {"templates": [t.to_dict() for t in items], "count": len(items)}


@router.get(
    "/api/alert-prompts/scorecards",
    dependencies=[Depends(require_any_permission(_READ_PERMS))],
)
def get_all_scorecards(
    window_days: int = 30,
    session: Session = Depends(get_db_session),
):
    """Per-template AI scorecard from AIFeedback ledger.

    Returns a dict keyed by template_id:
      {
        "sample_size": N,
        "agreement_pct": 0-100 | null,
        "fp_rate": 0-100,
        "btp_rate": 0-100,
        "tp_rate": 0-100,
        "tuning_needed": bool
      }

    tuning_needed = agreement_pct < 60 AND sample_size >= 10.
    """
    from datetime import datetime, timedelta, timezone


    try:
        pass
    except Exception:
        return {"window_days": window_days, "scorecards": {}}

    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)

    # Fix 3: dedup by (alert_id, template_id) keeping max(id) per pair —
    # mirrors the same dedup applied in bob_eval_service._fetch_deduped_feedback.
    # Without this, a pending (circuit-breaker) row and a later resolved row for
    # the same alert inflate sample_size but the pending row has agreement=NULL,
    # silently skewing the agreement_pct denominator.
    from sqlalchemy import text as _text
    is_pg = (
        session.bind is not None and
        session.bind.dialect.name == "postgresql"
    )
    dedup_sql = _text("""
        SELECT alert_prompt_template_id, agreement, human_verdict
        FROM ai_feedback
        WHERE id IN (
            SELECT MAX(id)
            FROM ai_feedback
            WHERE alert_prompt_template_id IS NOT NULL
              AND created_at >= :cutoff
            GROUP BY alert_id, alert_prompt_template_id
        )
        AND alert_prompt_template_id IS NOT NULL
    """)
    raw_rows = session.execute(dedup_sql, {"cutoff": cutoff}).fetchall()
    rows = [(r[0], r[1], r[2]) for r in raw_rows]

    # Aggregate in Python — the sample size per template is bounded by
    # analyst throughput (order of hundreds/month), so this is fine.
    buckets: dict[int, dict] = {}
    for tpl_id, agreement, verdict in rows:
        b = buckets.setdefault(
            tpl_id,
            {"sample_size": 0, "agreed": 0, "evaluated": 0,
             "fp": 0, "btp": 0, "tp": 0},
        )
        b["sample_size"] += 1
        if agreement is not None:
            b["evaluated"] += 1
            if agreement:
                b["agreed"] += 1
        if verdict == "false_positive":
            b["fp"] += 1
        elif verdict == "benign_true_positive":
            b["btp"] += 1
        elif verdict == "true_positive":
            b["tp"] += 1

    def _pct(num: int, denom: int) -> Optional[float]:
        if denom <= 0:
            return None
        return round(100.0 * num / denom, 1)

    scorecards: dict[int, dict] = {}
    for tpl_id, b in buckets.items():
        n = b["sample_size"]
        agreement_pct = _pct(b["agreed"], b["evaluated"])
        scorecards[tpl_id] = {
            "sample_size": n,
            "agreement_pct": agreement_pct,
            "fp_rate": _pct(b["fp"], n),
            "btp_rate": _pct(b["btp"], n),
            "tp_rate": _pct(b["tp"], n),
            "tuning_needed": (
                n >= 10 and agreement_pct is not None and agreement_pct < 60
            ),
        }

    return {"window_days": window_days, "scorecards": scorecards}


@router.get(
    "/api/alert-prompts/{template_id}",
    dependencies=[Depends(require_any_permission(_READ_PERMS))],
)
def get_alert_prompt(
    template_id: int,
    session: Session = Depends(get_db_session),
):
    repo = AlertPromptRepository(session)
    tmpl = repo.get_by_id(template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Alert prompt template not found")
    return tmpl.to_dict()


def _check_confidence_threshold_permission(
    user: User,
    data: "BaseModel",
    *,
    current_value: Optional[int] = None,
) -> None:
    """v0.22.1 (L6): confidence_threshold_override changes require system:settings.

    Distinguishes "field omitted" from "explicit null" via Pydantic's
    model_fields_set. Any change to the resulting stored value — including
    clearing a non-null override to NULL by sending an explicit null payload —
    requires system:settings. Closes the v0.21.x bypass where a user with only
    playbook:create/update could revert a system-tier strict threshold to the
    env-default by sending `confidence_threshold_override: null`.
    """
    if "confidence_threshold_override" not in data.model_fields_set:
        return
    incoming = data.confidence_threshold_override
    if incoming == current_value:
        return
    has_perm = any(
        p.name == "system:settings"
        for role in (user.roles or [])
        for p in (role.permissions or [])
    )
    if not has_perm:
        raise HTTPException(
            status_code=403,
            detail="system:settings required to change confidence_threshold_override",
        )


@router.post(
    "/api/alert-prompts",
    dependencies=[Depends(require_any_permission(_MANAGE_PERMS))],
)
def create_alert_prompt(
    data: AlertPromptCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    _check_confidence_threshold_permission(current_user, data, current_value=None)
    repo = AlertPromptRepository(session)
    existing = repo.get_by_name(data.name)
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"Alert prompt template with name '{data.name}' already exists",
        )
    try:
        tmpl = repo.create(
            name=data.name,
            prompt_text=data.prompt_text,
            description=data.description,
            enabled=data.enabled,
            rule_ids=data.rule_ids,
            rule_groups=data.rule_groups,
            rule_id_pattern=data.rule_id_pattern,
            mitre_techniques=data.mitre_techniques,
            mitre_tactics=data.mitre_tactics,
            priority=data.priority,
            investigation_checklist_text=data.investigation_checklist_text,
            severity_hint=data.severity_hint,
            expected_outputs=data.expected_outputs,
            created_by_id=current_user.id,
            confidence_threshold_override=data.confidence_threshold_override,
        )
        session.commit()
    except HTTPException:
        raise
    except Exception:
        session.rollback()
        logger.exception("Failed to create alert prompt template")
        raise HTTPException(status_code=500, detail="Failed to create template")
    return tmpl.to_dict()


@router.put(
    "/api/alert-prompts/{template_id}",
    dependencies=[Depends(require_any_permission(_MANAGE_PERMS))],
)
def update_alert_prompt(
    template_id: int,
    data: AlertPromptUpdate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    repo = AlertPromptRepository(session)
    tmpl = repo.get_by_id(template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Alert prompt template not found")

    # v0.22.1 (L6): gate is now incoming-vs-stored, so an explicit null that
    # would clear a non-null override is treated as a change and requires
    # system:settings. Must run AFTER tmpl is loaded so current_value is known.
    _check_confidence_threshold_permission(
        current_user, data, current_value=tmpl.confidence_threshold_override
    )

    # Name uniqueness on rename
    if data.name and data.name != tmpl.name:
        other = repo.get_by_name(data.name)
        if other and other.id != tmpl.id:
            raise HTTPException(
                status_code=409,
                detail=f"Another template with name '{data.name}' already exists",
            )

    try:
        repo.update(tmpl, **data.model_dump(exclude_unset=True))
        session.commit()
    except HTTPException:
        raise
    except Exception:
        session.rollback()
        logger.exception("Failed to update alert prompt template")
        raise HTTPException(status_code=500, detail="Failed to update template")
    return tmpl.to_dict()


@router.delete(
    "/api/alert-prompts/{template_id}",
    dependencies=[Depends(require_any_permission(_MANAGE_PERMS))],
)
def delete_alert_prompt(
    template_id: int,
    session: Session = Depends(get_db_session),
):
    repo = AlertPromptRepository(session)
    tmpl = repo.get_by_id(template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Alert prompt template not found")
    try:
        repo.delete(tmpl)
        session.commit()
    except Exception:
        session.rollback()
        logger.exception("Failed to delete alert prompt template")
        raise HTTPException(status_code=500, detail="Failed to delete template")
    return {"deleted": True, "id": template_id}


@router.post(
    "/api/alert-prompts/resolve",
    dependencies=[Depends(require_any_permission(_READ_PERMS))],
)
def resolve_alert_prompt(
    payload: ResolveRequest,
    session: Session = Depends(get_db_session),
):
    """Preview/debug endpoint — given an alert dict, return the matched template.

    Returns ``{"matched": null}`` if nothing matches.
    """
    svc = AlertPromptService(session)
    tmpl = svc.resolve_template_for_alert(payload.alert or {})
    if not tmpl:
        return {"matched": None, "rendered_prompt": None}
    rendered = svc.render_system_prompt(tmpl, payload.alert)
    return {"matched": tmpl.to_dict(), "rendered_prompt": rendered}


# ---------------------------------------------------------------------------
# HTML page
# ---------------------------------------------------------------------------


@router.get("/alert-prompts", response_class=HTMLResponse)
def alert_prompts_page(
    request: Request,
    _user: User = Depends(require_page_auth),
):
    return _templates.TemplateResponse(
        request=request,
        name="alert_prompt_templates.html",
    )


@router.get("/ai-scorecard", response_class=HTMLResponse)
def ai_scorecard_page(
    request: Request,
    _user: User = Depends(require_page_auth),
):
    """Per-template Bob-vs-human agreement dashboard (v0.10.12).

    Consumes the existing ``/api/alert-prompts/scorecards`` endpoint plus
    ``/api/alert-prompts`` for template names. Surfaces which templates are
    pulling their weight and which need tuning attention.
    """
    return _templates.TemplateResponse(
        request=request,
        name="ai_scorecard.html",
    )
