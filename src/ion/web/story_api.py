"""Story API — JSON-DAG playbook automation (v0.11.0).

Endpoints:
- ``GET    /api/stories``                     list
- ``GET    /api/stories/{id}``                fetch one
- ``POST   /api/stories``                     create from JSON
- ``PUT    /api/stories/{id}``                update
- ``DELETE /api/stories/{id}``                delete
- ``POST   /api/stories/{id}/run``            execute against a trigger
- ``GET    /api/stories/{id}/runs``           list past runs
- ``GET    /api/story-runs/{run_id}``         run detail
- ``GET    /api/stories/step-types``          public step catalogue
- ``GET    /stories``                         admin list page
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ion.auth.dependencies import (
    require_page_auth,
    require_permission,
)
from ion.models.story import Story, StoryRun
from ion.models.user import User
from ion.services import story_executor
from ion.web.api import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(tags=["stories"])

from ion.web.templating import make_templates  # noqa: E402

_templates = make_templates()


# ── Schemas ──────────────────────────────────────────────────────────────


class StoryCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    enabled: bool = True
    dag: Dict[str, Any] = Field(..., description="Full DAG JSON object")


class StoryUpdate(BaseModel):
    name: Optional[str] = Field(default=None, max_length=255)
    description: Optional[str] = None
    enabled: Optional[bool] = None
    dag: Optional[Dict[str, Any]] = None


class StoryRunRequest(BaseModel):
    case_id: Optional[int] = None
    alert_id: Optional[str] = None
    extra_context: Optional[Dict[str, Any]] = None


def _serialise(story: Story, *, include_dag: bool = True) -> dict:
    out = {
        "id": story.id,
        "name": story.name,
        "description": story.description,
        "enabled": story.enabled,
        "schema_version": story.schema_version,
        "created_by": story.created_by,
        "created_at": story.created_at.isoformat() if story.created_at else None,
        "updated_at": story.updated_at.isoformat() if story.updated_at else None,
    }
    if include_dag:
        try:
            out["dag"] = json.loads(story.dag_json or "{}")
        except (TypeError, ValueError):
            out["dag"] = {}
    return out


def _serialise_run(run: StoryRun) -> dict:
    try:
        steps = json.loads(run.step_outputs_json) if run.step_outputs_json else {}
    except (TypeError, ValueError):
        steps = {}
    return {
        "id": run.id,
        "story_id": run.story_id,
        "status": run.status,
        "case_id": run.case_id,
        "alert_id": run.alert_id,
        "triggered_by": run.triggered_by,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "step_outputs": steps,
        "error": run.error,
    }


# ── Payloads shared with the /ui fragments ───────────────────────────────
#
# The ordering, the enabled_only filter and the runs limit cap used to sit
# inline in the two JSON routes below. ion/web/ui/stories.py renders the same
# two reads as HTML, and a second copy of a query is the pair that drifts:
# one side would keep showing disabled stories, or stop capping the run
# limit, after the other was changed.

#: Most runs any caller can ask for in one request.
RUNS_LIMIT_CAP = 200


def list_payload(session: Session, *, enabled_only: bool = False) -> dict:
    """Every story, newest first, without its DAG.

    `include_dag=False` matches what the list has always returned: the rail
    shows a name and a badge, and a page carrying every story's full DAG
    would grow with the estate for no reader.
    """
    q = session.query(Story).order_by(Story.id.desc())
    if enabled_only:
        q = q.filter(Story.enabled.is_(True))
    items = q.all()
    return {
        "stories": [_serialise(s, include_dag=False) for s in items],
        "count": len(items),
    }


def dag_is_readable(dag_json: str | None) -> bool:
    """Whether the stored DAG text parses as JSON.

    `_serialise` turns an unparseable `dag_json` into `{}` and says nothing,
    which is the same swallow the fragments exist to remove: an empty object
    is a story with no steps, and a story whose text will not parse is a
    story whose steps are unknown. A JSON client got `{}` too, so this is
    reported rather than only shown.
    """
    try:
        json.loads(dag_json or "{}")
    except (TypeError, ValueError):
        return False
    return True


def story_payload(session: Session, story_id: int) -> dict | None:
    """One story with its DAG, or None when there is no such row.

    None rather than a raised 404 because the two callers want opposite
    things from a missing story: the JSON endpoint owes a client a 404, and
    the editor fragment owes a reader a pane that says the story is gone.
    Returning the absence lets each say its own thing about it.

    `dag_readable` is additive: every existing key keeps its name, type and
    value, and a caller that ignores it sees exactly what it saw before.
    """
    row = session.get(Story, story_id)
    if row is None:
        return None
    payload = _serialise(row)
    payload["dag_readable"] = dag_is_readable(row.dag_json)
    return payload


def runs_payload(session: Session, story_id: int, *, limit: int = 50) -> dict:
    """One story's most recent runs, newest first.

    The cap is here rather than at each caller. A fragment asking for its
    own limit would be a second answer to "how many runs will this endpoint
    ever return", and the heading that says how many are shown reads this
    list rather than the request.
    """
    rows = (
        session.query(StoryRun)
        .filter(StoryRun.story_id == story_id)
        .order_by(StoryRun.id.desc())
        .limit(min(limit, RUNS_LIMIT_CAP))
        .all()
    )
    return {"runs": [_serialise_run(r) for r in rows], "count": len(rows)}


# ── List + CRUD ──────────────────────────────────────────────────────────


@router.get("/api/stories")
def list_stories(
    enabled_only: bool = False,
    current_user: User = Depends(require_permission("playbook:read")),
    session: Session = Depends(get_db_session),
):
    return list_payload(session, enabled_only=enabled_only)


@router.get("/api/stories/step-types")
def get_step_types(
    current_user: User = Depends(require_permission("playbook:read")),
):
    """Public catalogue of step types the executor knows how to run."""
    return {"step_types": story_executor.list_step_types()}


@router.get("/api/stories/{story_id}")
def get_story(
    story_id: int,
    current_user: User = Depends(require_permission("playbook:read")),
    session: Session = Depends(get_db_session),
):
    payload = story_payload(session, story_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Story not found")
    return payload


@router.post("/api/stories")
def create_story(
    body: StoryCreate,
    current_user: User = Depends(require_permission("playbook:create")),
    session: Session = Depends(get_db_session),
):
    errors = story_executor.validate_dag(body.dag)
    if errors:
        raise HTTPException(status_code=400, detail={"validation_errors": errors})
    s = Story(
        name=body.name,
        description=body.description,
        enabled=body.enabled,
        dag_json=json.dumps(body.dag, default=str),
        created_by=current_user.id if current_user else None,
    )
    session.add(s)
    session.commit()
    session.refresh(s)
    return _serialise(s)


@router.put("/api/stories/{story_id}")
def update_story(
    story_id: int,
    body: StoryUpdate,
    current_user: User = Depends(require_permission("playbook:update")),
    session: Session = Depends(get_db_session),
):
    s = session.get(Story, story_id)
    if not s:
        raise HTTPException(status_code=404, detail="Story not found")
    if body.dag is not None:
        errors = story_executor.validate_dag(body.dag)
        if errors:
            raise HTTPException(status_code=400, detail={"validation_errors": errors})
        s.dag_json = json.dumps(body.dag, default=str)
    if body.name is not None:
        s.name = body.name
    if body.description is not None:
        s.description = body.description
    if body.enabled is not None:
        s.enabled = body.enabled
    session.commit()
    session.refresh(s)
    return _serialise(s)


@router.delete("/api/stories/{story_id}")
def delete_story(
    story_id: int,
    current_user: User = Depends(require_permission("playbook:delete")),
    session: Session = Depends(get_db_session),
):
    s = session.get(Story, story_id)
    if not s:
        raise HTTPException(status_code=404, detail="Story not found")
    session.delete(s)
    session.commit()
    return {"deleted": True, "id": story_id}


# ── Execution ────────────────────────────────────────────────────────────


@router.post("/api/stories/{story_id}/run")
def run_story(
    story_id: int,
    body: StoryRunRequest,
    current_user: User = Depends(require_permission("playbook:execute")),
    session: Session = Depends(get_db_session),
):
    """Execute a Story synchronously against a trigger entity.

    Returns the run record + step outputs. Long-running steps (Bob
    investigation can take 30 s) block the request — fine for v0.11.0
    where stories are short. Background execution lands later if needed.
    """
    s = session.get(Story, story_id)
    if not s:
        raise HTTPException(status_code=404, detail="Story not found")
    if not s.enabled:
        raise HTTPException(status_code=400, detail="Story is disabled")
    try:
        dag = json.loads(s.dag_json or "{}")
    except (TypeError, ValueError):
        raise HTTPException(status_code=500, detail="Story DAG is corrupt")

    # Persist a run row up front so a failure mid-execution still leaves
    # an audit trail in story_runs.
    run = StoryRun(
        story_id=story_id,
        case_id=body.case_id,
        alert_id=body.alert_id,
        triggered_by=current_user.id if current_user else None,
        status="running",
    )
    session.add(run)
    session.commit()

    trigger = {
        "case_id": body.case_id,
        "alert_id": body.alert_id,
        "user_id": current_user.id if current_user else None,
        "story_name": s.name,
    }
    if body.extra_context:
        trigger.update(body.extra_context)

    result = story_executor.execute_story(dag, trigger, session)
    run.status = result["status"]
    run.step_outputs_json = json.dumps(result.get("step_outputs", {}), default=str)
    run.error = result.get("error")
    from datetime import datetime
    run.completed_at = datetime.utcnow()
    session.commit()
    session.refresh(run)
    return _serialise_run(run)


@router.get("/api/stories/{story_id}/runs")
def list_story_runs(
    story_id: int,
    limit: int = 50,
    current_user: User = Depends(require_permission("playbook:read")),
    session: Session = Depends(get_db_session),
):
    return runs_payload(session, story_id, limit=limit)


@router.get("/api/story-runs/{run_id}")
def get_story_run(
    run_id: int,
    current_user: User = Depends(require_permission("playbook:read")),
    session: Session = Depends(get_db_session),
):
    run = session.get(StoryRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return _serialise_run(run)


# ── Admin page ───────────────────────────────────────────────────────────


@router.get("/stories", response_class=HTMLResponse)
def stories_page(
    request: Request,
    _user: User = Depends(require_page_auth),
):
    return _templates.TemplateResponse(
        request=request,
        name="stories.html",
    )
