"""GitLab integration API — config, issues, labels, milestones, members.

Extracted from web/api.py as the first increment of the god-module split
(finding #14). Mounted at the /api prefix in server.py, preserving the original
/api/gitlab/* paths. Self-contained: integration calls only, no DB session.
"""
import asyncio
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ion.auth.dependencies import require_admin, require_permission
from ion.core.config import get_gitlab_config
from ion.core.safe_errors import safe_error
from ion.models.user import User
from ion.services.gitlab_service import (
    GitLabError,
    get_gitlab_service,
    reset_gitlab_service,
)

router = APIRouter()


# Pydantic models for GitLab requests
class GitLabConfigUpdate(BaseModel):
    """Request to update GitLab configuration."""

    url: str
    token: str
    project_id: str


class GitLabIssueCreate(BaseModel):
    """Request to create a GitLab issue."""

    title: str
    description: Optional[str] = None
    labels: Optional[List[str]] = None
    assignee_ids: Optional[List[int]] = None
    milestone_id: Optional[int] = None
    due_date: Optional[str] = None


class GitLabIssueUpdate(BaseModel):
    """Request to update a GitLab issue."""

    title: Optional[str] = None
    description: Optional[str] = None
    labels: Optional[List[str]] = None
    state_event: Optional[str] = None  # "close" or "reopen"
    assignee_ids: Optional[List[int]] = None
    milestone_id: Optional[int] = None
    due_date: Optional[str] = None


class GitLabCommentCreate(BaseModel):
    """Request to add a comment to an issue."""

    body: str


class GitLabLabelCreate(BaseModel):
    """Request to create a label."""

    name: str
    color: str
    description: Optional[str] = None


@router.get("/gitlab/config")
async def get_gitlab_config_endpoint(
    current_user: User = Depends(require_permission("template:read")),
):
    """Get current GitLab configuration status."""
    config = get_gitlab_config()
    return {
        "enabled": config["enabled"],
        "url": config["url"],
        "project_id": config["project_id"],
        "has_token": bool(config["token"]),
    }


@router.post("/gitlab/config")
async def update_gitlab_config_endpoint(
    config_update: GitLabConfigUpdate,
    current_user: User = Depends(require_admin),
):
    """Update GitLab configuration (admin only).

    Note: This saves to the config file and resets the service.
    """
    import os

    from ion.core.config import get_config

    # Get current config
    config = get_config()

    # Update GitLab settings
    config.gitlab_enabled = True
    config.gitlab_url = config_update.url
    config.gitlab_token = config_update.token
    config.gitlab_project_id = config_update.project_id

    # Save to config file
    data_dir = os.environ.get("ION_DATA_DIR")
    if data_dir:
        config_path = Path(data_dir) / ".ion" / "config.json"
    else:
        config_path = Path.cwd() / ".ion" / "config.json"

    config.to_file(config_path)

    # Reset the service to pick up new config
    reset_gitlab_service()

    # Test connection
    service = get_gitlab_service()
    connection_result = await service.test_connection()
    await service.close()

    return {
        "success": True,
        "message": "GitLab configuration saved",
        "connection": connection_result,
    }


@router.delete("/gitlab/config")
async def disable_gitlab_config_endpoint(
    current_user: User = Depends(require_admin),
):
    """Disable GitLab integration (admin only)."""
    import os

    from ion.core.config import get_config

    config = get_config()
    config.gitlab_enabled = False
    config.gitlab_url = ""
    config.gitlab_token = ""
    config.gitlab_project_id = ""

    data_dir = os.environ.get("ION_DATA_DIR")
    if data_dir:
        config_path = Path(data_dir) / ".ion" / "config.json"
    else:
        config_path = Path.cwd() / ".ion" / "config.json"

    config.to_file(config_path)
    reset_gitlab_service()

    return {"success": True, "message": "GitLab integration disabled"}


@router.get("/gitlab/test")
async def test_gitlab_connection(
    current_user: User = Depends(require_permission("template:read")),
):
    """Test the GitLab connection."""
    service = get_gitlab_service()
    try:
        result = await service.test_connection()
        return result
    finally:
        await service.close()


@router.get("/gitlab/issues")
async def list_gitlab_issues(
    state: str = "all",
    labels: Optional[str] = None,
    search: Optional[str] = None,
    per_page: int = 20,
    page: int = 1,
    scope: Optional[str] = None,
    author_username: Optional[str] = None,
    assignee_username: Optional[str] = None,
    my_issues: bool = False,
    current_user: User = Depends(require_permission("template:read")),
):
    """List GitLab issues.

    Args:
        state: Filter by state ("opened", "closed", "all")
        labels: Comma-separated list of labels
        search: Search in title and description
        per_page: Number of issues per page
        page: Page number
        scope: GitLab scope filter ("created_by_me", "assigned_to_me", "all")
        author_username: Filter by author GitLab username
        assignee_username: Filter by assignee GitLab username
        my_issues: If true, auto-filter to current user's GitLab username
    """
    service = get_gitlab_service()
    try:
        label_list = labels.split(",") if labels else None

        # Auto-filter to current user's GitLab username if requested
        # Fetches both assigned-to and created-by, then merges (deduped)
        if my_issues and not author_username and not assignee_username:
            gl_user = getattr(current_user, 'gitlab_username', None) or current_user.username
            assigned, authored = await asyncio.gather(
                service.list_issues(
                    state=state, labels=label_list, search=search,
                    per_page=per_page, page=page,
                    assignee_username=gl_user, scope=scope,
                ),
                service.list_issues(
                    state=state, labels=label_list, search=search,
                    per_page=per_page, page=page,
                    author_username=gl_user, scope=scope,
                ),
            )
            seen = set()
            issues = []
            for issue in assigned + authored:
                if issue.id not in seen:
                    seen.add(issue.id)
                    issues.append(issue)
            issues.sort(key=lambda i: i.updated_at, reverse=True)
            return {"issues": [issue.to_dict() for issue in issues]}

        issues = await service.list_issues(
            state=state,
            labels=label_list,
            search=search,
            per_page=per_page,
            page=page,
            author_username=author_username,
            assignee_username=assignee_username,
            scope=scope,
        )
        return {"issues": [issue.to_dict() for issue in issues]}
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=safe_error(e))
    finally:
        await service.close()


@router.get("/gitlab/issues/{issue_iid}")
async def get_gitlab_issue(
    issue_iid: int,
    current_user: User = Depends(require_permission("template:read")),
):
    """Get a specific GitLab issue."""
    service = get_gitlab_service()
    try:
        issue = await service.get_issue(issue_iid)
        return issue.to_dict()
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=safe_error(e))
    finally:
        await service.close()


@router.post("/gitlab/issues")
async def create_gitlab_issue(
    issue_data: GitLabIssueCreate,
    current_user: User = Depends(require_permission("template:create")),
):
    """Create a new GitLab issue."""
    service = get_gitlab_service()
    try:
        description = issue_data.description or ""
        sudo_user = None
        if service.sudo_enabled:
            # Impersonate: GitLab natively shows the real user
            sudo_user = current_user.username
        else:
            # Text attribution fallback
            display = current_user.display_name or current_user.username
            description += f"\n\n---\n*Created by {display} via ION*"
        issue = await service.create_issue(
            title=issue_data.title,
            description=description,
            labels=issue_data.labels,
            assignee_ids=issue_data.assignee_ids,
            milestone_id=issue_data.milestone_id,
            due_date=issue_data.due_date,
            sudo_user=sudo_user,
        )
        return issue.to_dict()
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=safe_error(e))
    finally:
        await service.close()


@router.put("/gitlab/issues/{issue_iid}")
async def update_gitlab_issue(
    issue_iid: int,
    issue_data: GitLabIssueUpdate,
    current_user: User = Depends(require_permission("template:update")),
):
    """Update a GitLab issue."""
    service = get_gitlab_service()
    try:
        issue = await service.update_issue(
            issue_iid=issue_iid,
            title=issue_data.title,
            description=issue_data.description,
            labels=issue_data.labels,
            state_event=issue_data.state_event,
            assignee_ids=issue_data.assignee_ids,
            milestone_id=issue_data.milestone_id,
            due_date=issue_data.due_date,
        )
        return issue.to_dict()
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=safe_error(e))
    finally:
        await service.close()


@router.post("/gitlab/issues/{issue_iid}/close")
async def close_gitlab_issue(
    issue_iid: int,
    current_user: User = Depends(require_permission("template:update")),
):
    """Close a GitLab issue."""
    service = get_gitlab_service()
    try:
        issue = await service.close_issue(issue_iid)
        return issue.to_dict()
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=safe_error(e))
    finally:
        await service.close()


@router.post("/gitlab/issues/{issue_iid}/reopen")
async def reopen_gitlab_issue(
    issue_iid: int,
    current_user: User = Depends(require_permission("template:update")),
):
    """Reopen a closed GitLab issue."""
    service = get_gitlab_service()
    try:
        issue = await service.reopen_issue(issue_iid)
        return issue.to_dict()
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=safe_error(e))
    finally:
        await service.close()


@router.delete("/gitlab/issues/{issue_iid}")
async def delete_gitlab_issue(
    issue_iid: int,
    current_user: User = Depends(require_permission("template:delete")),
):
    """Delete a GitLab issue."""
    service = get_gitlab_service()
    try:
        await service.delete_issue(issue_iid)
        return {"success": True, "message": f"Issue #{issue_iid} deleted"}
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=safe_error(e))
    finally:
        await service.close()


@router.get("/gitlab/issues/{issue_iid}/comments")
async def list_gitlab_issue_comments(
    issue_iid: int,
    per_page: int = 20,
    page: int = 1,
    current_user: User = Depends(require_permission("template:read")),
):
    """List comments on a GitLab issue."""
    service = get_gitlab_service()
    try:
        comments = await service.list_issue_comments(
            issue_iid=issue_iid,
            per_page=per_page,
            page=page,
        )
        return {"comments": [comment.to_dict() for comment in comments]}
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=safe_error(e))
    finally:
        await service.close()


@router.post("/gitlab/issues/{issue_iid}/comments")
async def add_gitlab_issue_comment(
    issue_iid: int,
    comment_data: GitLabCommentCreate,
    current_user: User = Depends(require_permission("template:create")),
):
    """Add a comment to a GitLab issue."""
    service = get_gitlab_service()
    try:
        sudo_user = None
        if service.sudo_enabled:
            # Impersonate: GitLab natively shows the real user
            sudo_user = current_user.username
            body = comment_data.body
        else:
            # Text attribution fallback
            display = current_user.display_name or current_user.username
            body = f"**{display}** (via ION):\n\n{comment_data.body}"
        comment = await service.add_issue_comment(
            issue_iid=issue_iid,
            body=body,
            sudo_user=sudo_user,
        )
        return comment.to_dict()
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=safe_error(e))
    finally:
        await service.close()


@router.get("/gitlab/labels")
async def list_gitlab_labels(
    current_user: User = Depends(require_permission("template:read")),
):
    """List all labels in the GitLab project."""
    service = get_gitlab_service()
    try:
        labels = await service.list_labels()
        return {"labels": labels}
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=safe_error(e))
    finally:
        await service.close()


@router.post("/gitlab/labels")
async def create_gitlab_label(
    label_data: GitLabLabelCreate,
    current_user: User = Depends(require_permission("template:create")),
):
    """Create a new label in the GitLab project."""
    service = get_gitlab_service()
    try:
        label = await service.create_label(
            name=label_data.name,
            color=label_data.color,
            description=label_data.description,
        )
        return label
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=safe_error(e))
    finally:
        await service.close()


@router.get("/gitlab/milestones")
async def list_gitlab_milestones(
    state: str = "active",
    current_user: User = Depends(require_permission("template:read")),
):
    """List milestones in the GitLab project."""
    service = get_gitlab_service()
    try:
        milestones = await service.list_milestones(state=state)
        return {"milestones": milestones}
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=safe_error(e))
    finally:
        await service.close()


@router.get("/gitlab/members")
async def list_gitlab_members(
    current_user: User = Depends(require_permission("template:read")),
):
    """List project members for assignment."""
    service = get_gitlab_service()
    try:
        members = await service.list_members()
        return {"members": members}
    except GitLabError as e:
        raise HTTPException(status_code=e.status_code or 500, detail=safe_error(e))
    finally:
        await service.close()
