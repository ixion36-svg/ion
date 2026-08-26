"""Arkime connector for integration management.

Wraps the ArkimeService to plug into the connector registry so the
Integrations page shows an "Arkime" card with a working Test button.
"""

from typing import Any, Dict

from ion.services.arkime_service import (
    ArkimeService,
    get_arkime_service,
    reset_arkime_service,
)
from ion.services.connectors.base import BaseConnector


class ArkimeConnector(BaseConnector):
    """Connector for Arkime viewer integration."""

    CONNECTOR_TYPE = "arkime"
    DISPLAY_NAME = "Arkime"

    def __init__(self):
        self._service: ArkimeService = get_arkime_service()

    @property
    def is_configured(self) -> bool:
        return self._service.is_configured

    async def configure(self, config: Dict[str, Any]) -> bool:
        """Reset the singleton so it picks up the new .env / config.json values."""
        reset_arkime_service()
        self._service = get_arkime_service()
        return True

    async def test_connection(self) -> Dict[str, Any]:
        """Probe the Arkime viewer and return the usual connector status payload."""
        result = await self._service.test_connection()
        return result

    async def sync(self, **kwargs) -> Dict[str, Any]:
        """Arkime is read-only for ION — nothing to sync."""
        return {"synced": True, "message": "Arkime is pull-only; nothing to sync."}

    def get_config_schema(self) -> Dict[str, Any]:
        # ArkimeService is HTTP Basic only — do not re-add Keycloak/API-key
        # fields here without restoring them in the service first.
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "title": "Arkime viewer URL",
                    "description": "Base URL of the Arkime viewer (e.g., https://viewer.example.com)",
                    "format": "uri",
                },
                "username": {
                    "type": "string",
                    "title": "HTTP basic username",
                },
                "password": {
                    "type": "string",
                    "title": "HTTP basic password",
                    "format": "password",
                },
                "verify_ssl": {
                    "type": "boolean",
                    "title": "Verify SSL",
                    "default": True,
                },
            },
            "required": ["url", "username", "password"],
        }

    def get_status_info(self) -> Dict[str, Any]:
        info = super().get_status_info()
        if self.is_configured:
            info["url"] = self._service.url
            info["auth_mode"] = "basic" if self._service._has_basic else "none"
        return info
