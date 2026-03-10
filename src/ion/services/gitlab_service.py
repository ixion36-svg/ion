"""GitLab integration service for ION.

Provides functionality to interact with GitLab issues and projects.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime
import httpx

from ion.core.config import get_gitlab_config


@dataclass
class GitLabIssue:
    """Represents a GitLab issue."""

    id: int
    iid: int  # Project-level issue ID
    title: str
    description: str
    state: str  # "opened" or "closed"
    labels: List[str]
    assignees: List[str]
    author: str
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime]
    web_url: str
    milestone: Optional[str] = None
    due_date: Optional[str] = None

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "GitLabIssue":
        """Create GitLabIssue from API response data."""
        return cls(
            id=data["id"],
            iid=data["iid"],
            title=data["title"],
            description=data.get("description") or "",
            state=data["state"],
            labels=data.get("labels", []),
            assignees=[a["username"] for a in data.get("assignees", [])],
            author=data.get("author", {}).get("username", "unknown"),
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(data["updated_at"].replace("Z", "+00:00")),
            closed_at=(
                datetime.fromisoformat(data["closed_at"].replace("Z", "+00:00"))
                if data.get("closed_at")
                else None
            ),
            web_url=data["web_url"],
            milestone=data.get("milestone", {}).get("title") if data.get("milestone") else None,
            due_date=data.get("due_date"),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            "id": self.id,
            "iid": self.iid,
            "title": self.title,
            "description": self.description,
            "state": self.state,
            "labels": self.labels,
            "assignees": self.assignees,
            "author": self.author,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "web_url": self.web_url,
            "milestone": self.milestone,
            "due_date": self.due_date,
        }


@dataclass
class GitLabComment:
    """Represents a GitLab issue comment (note)."""

    id: int
    body: str
    author: str
    created_at: datetime
    updated_at: datetime
    system: bool  # True for system-generated notes

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "GitLabComment":
        """Create GitLabComment from API response data."""
        return cls(
            id=data["id"],
            body=data["body"],
            author=data.get("author", {}).get("username", "unknown"),
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(data["updated_at"].replace("Z", "+00:00")),
            system=data.get("system", False),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            "id": self.id,
            "body": self.body,
            "author": self.author,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "system": self.system,
        }


class GitLabError(Exception):
    """Exception raised for GitLab API errors."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class GitLabService:
    """Service for interacting with GitLab API."""

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        project_id: Optional[str] = None,
    ):
        """Initialize GitLab service.

        Args:
            url: GitLab instance URL (e.g., https://gitlab.example.com)
            token: Personal access token with api scope
            project_id: Project ID or path (e.g., "group/project" or "123")

        If not provided, values are loaded from configuration.
        """
        config = get_gitlab_config()
        self.url = (url or config["url"]).rstrip("/")
        self.token = token or config["token"]
        self.project_id = project_id or config["project_id"]
        self.verify_ssl = config.get("verify_ssl", True)
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def is_configured(self) -> bool:
        """Check if GitLab integration is properly configured."""
        return bool(self.url and self.token and self.project_id)

    @property
    def api_url(self) -> str:
        """Get the GitLab API base URL."""
        return f"{self.url}/api/v4"

    @property
    def project_api_url(self) -> str:
        """Get the project-specific API URL."""
        # URL-encode the project ID (for paths like "group/project")
        import urllib.parse

        encoded_project = urllib.parse.quote(self.project_id, safe="")
        return f"{self.api_url}/projects/{encoded_project}"

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication."""
        return {
            "PRIVATE-TOKEN": self.token,
            "Content-Type": "application/json",
        }

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            from ion.core.config import get_ssl_verify
            self._client = httpx.AsyncClient(
                headers=self._get_headers(),
                timeout=httpx.Timeout(60.0, connect=10.0),
                verify=get_ssl_verify(self.verify_ssl),
            )
        return self._client

    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Any:
        """Make an authenticated request to GitLab API."""
        if not self.is_configured:
            raise GitLabError("GitLab integration is not configured")

        # Use a fresh client per request to avoid connection issues with concurrent requests
        try:
            from ion.core.config import get_ssl_verify
            async with httpx.AsyncClient(
                headers=self._get_headers(),
                timeout=httpx.Timeout(60.0, connect=10.0),
                verify=get_ssl_verify(self.verify_ssl),
            ) as client:
                response = await client.request(method, url, **kwargs)
        except httpx.ConnectError as e:
            raise GitLabError(f"Failed to connect to GitLab: {e}")
        except httpx.ReadError as e:
            raise GitLabError(f"Connection error reading from GitLab: {e}")
        except httpx.TimeoutException as e:
            raise GitLabError(f"Request to GitLab timed out: {e}")
        except httpx.HTTPError as e:
            raise GitLabError(f"HTTP error communicating with GitLab: {e}")

        if response.status_code >= 400:
            try:
                error_data = response.json()
                error_msg = error_data.get("message") or error_data.get("error") or str(error_data)
            except Exception:
                error_msg = response.text
            raise GitLabError(f"GitLab API error: {error_msg}", response.status_code)

        if response.status_code == 204:
            return None
        return response.json()

    async def test_connection(self) -> Dict[str, Any]:
        """Test the GitLab connection and return project info."""
        if not self.is_configured:
            return {
                "connected": False,
                "error": "GitLab integration is not configured",
            }

        try:
            project = await self._request("GET", self.project_api_url)
            return {
                "connected": True,
                "project_name": project.get("name"),
                "project_path": project.get("path_with_namespace"),
                "web_url": project.get("web_url"),
            }
        except GitLabError as e:
            return {
                "connected": False,
                "error": str(e),
            }

    # Issue operations

    async def list_issues(
        self,
        state: str = "all",
        labels: Optional[List[str]] = None,
        search: Optional[str] = None,
        per_page: int = 20,
        page: int = 1,
    ) -> List[GitLabIssue]:
        """List issues in the project.

        Args:
            state: Filter by state ("opened", "closed", "all")
            labels: Filter by labels
            search: Search in title and description
            per_page: Number of issues per page
            page: Page number

        Returns:
            List of GitLabIssue objects
        """
        params: Dict[str, Any] = {
            "state": state,
            "per_page": per_page,
            "page": page,
            "order_by": "updated_at",
            "sort": "desc",
        }

        if labels:
            params["labels"] = ",".join(labels)
        if search:
            params["search"] = search

        data = await self._request(
            "GET",
            f"{self.project_api_url}/issues",
            params=params,
        )

        return [GitLabIssue.from_api_response(issue) for issue in data]

    async def get_issue(self, issue_iid: int) -> GitLabIssue:
        """Get a specific issue by its project-level ID (iid).

        Args:
            issue_iid: The project-level issue ID

        Returns:
            GitLabIssue object
        """
        data = await self._request("GET", f"{self.project_api_url}/issues/{issue_iid}")
        return GitLabIssue.from_api_response(data)

    async def create_issue(
        self,
        title: str,
        description: Optional[str] = None,
        labels: Optional[List[str]] = None,
        assignee_ids: Optional[List[int]] = None,
        milestone_id: Optional[int] = None,
        due_date: Optional[str] = None,
    ) -> GitLabIssue:
        """Create a new issue.

        Args:
            title: Issue title
            description: Issue description (Markdown supported)
            labels: List of label names
            assignee_ids: List of user IDs to assign
            milestone_id: Milestone ID
            due_date: Due date in YYYY-MM-DD format

        Returns:
            Created GitLabIssue object
        """
        payload: Dict[str, Any] = {"title": title}

        if description:
            payload["description"] = description
        if labels:
            payload["labels"] = ",".join(labels)
        if assignee_ids:
            payload["assignee_ids"] = assignee_ids
        if milestone_id:
            payload["milestone_id"] = milestone_id
        if due_date:
            payload["due_date"] = due_date

        data = await self._request(
            "POST",
            f"{self.project_api_url}/issues",
            json=payload,
        )

        return GitLabIssue.from_api_response(data)

    async def update_issue(
        self,
        issue_iid: int,
        title: Optional[str] = None,
        description: Optional[str] = None,
        labels: Optional[List[str]] = None,
        state_event: Optional[str] = None,  # "close" or "reopen"
        assignee_ids: Optional[List[int]] = None,
        milestone_id: Optional[int] = None,
        due_date: Optional[str] = None,
    ) -> GitLabIssue:
        """Update an existing issue.

        Args:
            issue_iid: The project-level issue ID
            title: New title
            description: New description
            labels: New labels (replaces existing)
            state_event: "close" or "reopen"
            assignee_ids: New assignees (replaces existing)
            milestone_id: New milestone
            due_date: New due date

        Returns:
            Updated GitLabIssue object
        """
        payload: Dict[str, Any] = {}

        if title is not None:
            payload["title"] = title
        if description is not None:
            payload["description"] = description
        if labels is not None:
            payload["labels"] = ",".join(labels)
        if state_event:
            payload["state_event"] = state_event
        if assignee_ids is not None:
            payload["assignee_ids"] = assignee_ids
        if milestone_id is not None:
            payload["milestone_id"] = milestone_id
        if due_date is not None:
            payload["due_date"] = due_date

        data = await self._request(
            "PUT",
            f"{self.project_api_url}/issues/{issue_iid}",
            json=payload,
        )

        return GitLabIssue.from_api_response(data)

    async def close_issue(self, issue_iid: int) -> GitLabIssue:
        """Close an issue.

        Args:
            issue_iid: The project-level issue ID

        Returns:
            Updated GitLabIssue object
        """
        return await self.update_issue(issue_iid, state_event="close")

    async def reopen_issue(self, issue_iid: int) -> GitLabIssue:
        """Reopen a closed issue.

        Args:
            issue_iid: The project-level issue ID

        Returns:
            Updated GitLabIssue object
        """
        return await self.update_issue(issue_iid, state_event="reopen")

    async def delete_issue(self, issue_iid: int) -> None:
        """Delete an issue.

        Args:
            issue_iid: The project-level issue ID
        """
        await self._request("DELETE", f"{self.project_api_url}/issues/{issue_iid}")

    # Comment operations

    async def list_issue_comments(
        self,
        issue_iid: int,
        per_page: int = 20,
        page: int = 1,
    ) -> List[GitLabComment]:
        """List comments (notes) on an issue.

        Args:
            issue_iid: The project-level issue ID
            per_page: Number of comments per page
            page: Page number

        Returns:
            List of GitLabComment objects
        """
        params = {
            "per_page": per_page,
            "page": page,
            "order_by": "created_at",
            "sort": "asc",
        }

        data = await self._request(
            "GET",
            f"{self.project_api_url}/issues/{issue_iid}/notes",
            params=params,
        )

        # Filter out system notes by default
        return [
            GitLabComment.from_api_response(note)
            for note in data
            if not note.get("system", False)
        ]

    async def add_issue_comment(self, issue_iid: int, body: str) -> GitLabComment:
        """Add a comment to an issue.

        Args:
            issue_iid: The project-level issue ID
            body: Comment body (Markdown supported)

        Returns:
            Created GitLabComment object
        """
        data = await self._request(
            "POST",
            f"{self.project_api_url}/issues/{issue_iid}/notes",
            json={"body": body},
        )

        return GitLabComment.from_api_response(data)

    # Label operations

    async def list_labels(self) -> List[Dict[str, Any]]:
        """List all labels in the project.

        Returns:
            List of label dictionaries with name, color, description
        """
        data = await self._request(
            "GET",
            f"{self.project_api_url}/labels",
            params={"per_page": 100},
        )

        return [
            {
                "name": label["name"],
                "color": label["color"],
                "description": label.get("description", ""),
            }
            for label in data
        ]

    async def create_label(
        self,
        name: str,
        color: str,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new label.

        Args:
            name: Label name
            color: Color in hex format (e.g., "#FF0000")
            description: Label description

        Returns:
            Created label dictionary
        """
        payload: Dict[str, Any] = {
            "name": name,
            "color": color,
        }
        if description:
            payload["description"] = description

        data = await self._request(
            "POST",
            f"{self.project_api_url}/labels",
            json=payload,
        )

        return {
            "name": data["name"],
            "color": data["color"],
            "description": data.get("description", ""),
        }

    # Milestone operations

    async def list_milestones(self, state: str = "active") -> List[Dict[str, Any]]:
        """List milestones in the project.

        Args:
            state: Filter by state ("active", "closed", "all")

        Returns:
            List of milestone dictionaries
        """
        data = await self._request(
            "GET",
            f"{self.project_api_url}/milestones",
            params={"state": state, "per_page": 100},
        )

        return [
            {
                "id": m["id"],
                "title": m["title"],
                "description": m.get("description", ""),
                "state": m["state"],
                "due_date": m.get("due_date"),
                "start_date": m.get("start_date"),
            }
            for m in data
        ]

    # Project members

    async def list_members(self) -> List[Dict[str, Any]]:
        """List project members for assignment.

        Returns:
            List of member dictionaries with id, username, name
        """
        data = await self._request(
            "GET",
            f"{self.project_api_url}/members/all",
            params={"per_page": 100},
        )

        return [
            {
                "id": m["id"],
                "username": m["username"],
                "name": m["name"],
            }
            for m in data
        ]


# Singleton instance
_gitlab_service: Optional[GitLabService] = None


def get_gitlab_service() -> GitLabService:
    """Get the global GitLab service instance."""
    global _gitlab_service
    if _gitlab_service is None:
        _gitlab_service = GitLabService()
    return _gitlab_service


def reset_gitlab_service():
    """Reset the global GitLab service instance (for config changes)."""
    global _gitlab_service
    _gitlab_service = None
