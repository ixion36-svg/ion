"""Kibana Cases connector for integration management.

Wraps KibanaCasesService and KibanaSyncService to provide a unified connector interface.
"""

from typing import Dict, Any, Optional

from ion.services.connectors.base import BaseConnector
from ion.services.connectors.version_compat import KIBANA_VERSIONS
from ion.services.kibana_cases_service import (
    KibanaCasesService,
    get_kibana_cases_service,
    reset_kibana_cases_service,
)
from ion.services.kibana_sync_service import (
    KibanaSyncService,
    get_kibana_sync_service,
    reset_kibana_sync_service,
)


class KibanaCasesConnector(BaseConnector):
    """Connector for Kibana Cases integration."""

    CONNECTOR_TYPE = "kibana_cases"
    DISPLAY_NAME = "Kibana Cases"
    SUPPORTED_VERSIONS = KIBANA_VERSIONS
    VERSION_KEY = "version"

    def __init__(self):
        self._cases_service: KibanaCasesService = get_kibana_cases_service()
        self._sync_service: KibanaSyncService = get_kibana_sync_service()

    @property
    def cases_service(self) -> KibanaCasesService:
        """Access the underlying Kibana Cases service."""
        return self._cases_service

    @property
    def sync_service(self) -> KibanaSyncService:
        """Access the underlying Kibana sync service."""
        return self._sync_service

    @property
    def is_configured(self) -> bool:
        """Check if Kibana Cases is configured and enabled."""
        return self._cases_service.enabled

    async def configure(self, config: Dict[str, Any]) -> bool:
        """Apply new configuration by resetting both services.

        Args:
            config: Configuration with connection settings.

        Returns:
            True if configuration was applied successfully.
        """
        reset_kibana_cases_service()
        reset_kibana_sync_service()
        self._cases_service = get_kibana_cases_service()
        self._sync_service = get_kibana_sync_service()

        # Restart background sync if enabled
        if self._cases_service.enabled:
            self.start_background_sync(interval_seconds=60)

        return True

    async def test_connection(self) -> Dict[str, Any]:
        """Test the Kibana connection.

        Adapts KibanaCasesService.test_connection() to the connector
        format expected by BaseConnector.healthcheck().
        """
        result = self._cases_service.test_connection()
        return {
            "connected": result.get("success", False),
            "version": result.get("version"),
            "status": result.get("status"),
            "error": result.get("error"),
        }

    async def sync(self, **kwargs) -> Dict[str, Any]:
        """Trigger a full sync of all Kibana-linked cases."""
        if not self.is_configured:
            return {
                "synced": False,
                "error": "Kibana Cases is not configured",
            }

        try:
            result = await self._sync_service.sync_all_cases()
            return {
                "synced": True,
                "comments_synced": result.get("synced", 0),
                "cases_processed": result.get("cases", 0),
            }
        except Exception as e:
            return {
                "synced": False,
                "error": str(e),
            }

    def start_background_sync(self, interval_seconds: int = 60):
        """Start the background sync task."""
        self._sync_service.start_background_sync(interval_seconds=interval_seconds)

    def stop_background_sync(self):
        """Stop the background sync task."""
        self._sync_service.stop_background_sync()

    def get_config_schema(self) -> Dict[str, Any]:
        """Get JSON schema for Kibana Cases configuration."""
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "title": "Kibana URL",
                    "description": "Kibana instance URL (e.g., https://kibana.example.com)",
                    "format": "uri",
                },
                "username": {
                    "type": "string",
                    "title": "Username",
                    "description": "Kibana username for authentication",
                },
                "password": {
                    "type": "string",
                    "title": "Password",
                    "description": "Kibana password",
                    "format": "password",
                },
                "space_id": {
                    "type": "string",
                    "title": "Space ID",
                    "description": "Kibana space ID (default: 'default')",
                    "default": "default",
                },
                "case_owner": {
                    "type": "string",
                    "title": "Case Owner",
                    "description": "Kibana case owner (default: 'securitySolution')",
                    "default": "securitySolution",
                },
            },
            "required": ["url"],
        }

    def get_status_info(self) -> Dict[str, Any]:
        """Get Kibana Cases connector status."""
        info = super().get_status_info()
        if self.is_configured:
            info["url"] = self._cases_service.config.get("url", "")
            info["space_id"] = self._cases_service.config.get("space_id", "default")
            info["background_sync_running"] = self._sync_service._running
        return info
