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
from ion.storage.alert_prompt_repository import AlertPromptRepository
from ion.services.alert_prompt_service import AlertPromptService
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
    priority: int = 100
    investigation_checklist_text: Optional[str] = None
    severity_hint: Optional[str] = None
    expected_outputs: Optional[List[str]] = None


class AlertPromptUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=255)
    prompt_text: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    rule_ids: Optional[List[str]] = None
    rule_groups: Optional[List[str]] = None
    rule_id_pattern: Optional[str] = None
    priority: Optional[int] = None
    investigation_checklist_text: Optional[str] = None
    severity_hint: Optional[str] = None
    expected_outputs: Optional[List[str]] = None


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


@router.post(
    "/api/alert-prompts",
    dependencies=[Depends(require_any_permission(_MANAGE_PERMS))],
)
def create_alert_prompt(
    data: AlertPromptCreate,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
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
            priority=data.priority,
            investigation_checklist_text=data.investigation_checklist_text,
            severity_hint=data.severity_hint,
            expected_outputs=data.expected_outputs,
            created_by_id=current_user.id,
        )
        session.commit()
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
    session: Session = Depends(get_db_session),
):
    repo = AlertPromptRepository(session)
    tmpl = repo.get_by_id(template_id)
    if not tmpl:
        raise HTTPException(status_code=404, detail="Alert prompt template not found")

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
