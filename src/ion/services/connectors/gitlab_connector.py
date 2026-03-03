"""GitLab connector for integration management.

Wraps the GitLabService to provide a unified connector interface.
"""

from typing import Dict, Any

from ion.services.connectors.base import BaseConnector
from ion.services.gitlab_service import (
    get_gitlab_service,
    reset_gitlab_service,
    GitLabService,
)


class GitLabConnector(BaseConnector):
    """Connector for GitLab integration."""

    CONNECTOR_TYPE = "gitlab"
    DISPLAY_NAME = "GitLab"

    def __init__(self):
        self._service: GitLabService = get_gitlab_service()

    @property
    def is_configured(self) -> bool:
        """Check if GitLab is configured."""
        return self._service.is_configured

    async def configure(self, config: Dict[str, Any]) -> bool:
        """Apply new configuration to the GitLab service.

        Args:
            config: Configuration with 'url', 'token', and 'project_id' keys.

        Returns:
            True if configuration was applied successfully.
        """
        # Reset the service to pick up new configuration
        reset_gitlab_service()
        self._service = get_gitlab_service()
        return True

    async def test_connection(self) -> Dict[str, Any]:
        """Test the GitLab connection."""
        return await self._service.test_connection()

    async def sync(self, **kwargs) -> Dict[str, Any]:
        """Sync GitLab issues.

        Args:
            **kwargs: Optional filters for issue sync.

        Returns:
            Dictionary with sync results.
        """
        if not self.is_configured:
            return {
                "synced": False,
                "error": "GitLab is not configured",
            }

        try:
            issues = await self._service.list_issues(
                state=kwargs.get("state", "opened"),
                per_page=kwargs.get("per_page", 50),
            )
            return {
                "synced": True,
                "issues_count": len(issues),
                "issues": [issue.to_dict() for issue in issues],
            }
        except Exception as e:
            return {
                "synced": False,
                "error": str(e),
            }

    def get_config_schema(self) -> Dict[str, Any]:
        """Get JSON schema for GitLab configuration."""
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "title": "GitLab URL",
                    "description": "GitLab instance URL (e.g., https://gitlab.example.com)",
                    "format": "uri",
                },
                "token": {
                    "type": "string",
                    "title": "Access Token",
                    "description": "Personal access token with API scope",
                    "format": "password",
                },
                "project_id": {
                    "type": "string",
                    "title": "Project ID",
                    "description": "Project ID or path (e.g., 'group/project' or '123')",
                },
            },
            "required": ["url", "token", "project_id"],
        }

    def get_status_info(self) -> Dict[str, Any]:
        """Get GitLab connector status."""
        info = super().get_status_info()
        if self.is_configured:
            info["url"] = self._service.url
            info["project_id"] = self._service.project_id
        return info
