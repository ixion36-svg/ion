"""OpenCTI connector for integration management.

Wraps the OpenCTIService to provide a unified connector interface.
"""

from typing import Dict, Any

from ion.services.connectors.base import BaseConnector
from ion.services.opencti_service import (
    get_opencti_service,
    reset_opencti_service,
    OpenCTIService,
)


class OpenCTIConnector(BaseConnector):
    """Connector for OpenCTI integration."""

    CONNECTOR_TYPE = "opencti"
    DISPLAY_NAME = "OpenCTI"

    def __init__(self):
        self._service: OpenCTIService = get_opencti_service()

    @property
    def is_configured(self) -> bool:
        """Check if OpenCTI is configured."""
        return self._service.is_configured

    async def configure(self, config: Dict[str, Any]) -> bool:
        """Apply new configuration to the OpenCTI service.

        Args:
            config: Configuration with 'url' and 'token' keys.

        Returns:
            True if configuration was applied successfully.
        """
        # Reset the service to pick up new configuration
        reset_opencti_service()
        self._service = get_opencti_service()
        return True

    async def test_connection(self) -> Dict[str, Any]:
        """Test the OpenCTI connection."""
        return await self._service.test_connection()

    async def sync(self, **kwargs) -> Dict[str, Any]:
        """Sync/enrich observables from OpenCTI.

        Args:
            **kwargs: Should contain 'observables' list with type/value dicts.

        Returns:
            Dictionary with enrichment results.
        """
        if not self.is_configured:
            return {
                "synced": False,
                "error": "OpenCTI is not configured",
            }

        observables = kwargs.get("observables", [])
        if not observables:
            return {
                "synced": True,
                "enriched_count": 0,
                "results": [],
            }

        try:
            results = await self._service.enrich_batch(observables)
            found_count = sum(1 for r in results if r.get("found"))
            return {
                "synced": True,
                "enriched_count": found_count,
                "total_count": len(results),
                "results": results,
            }
        except Exception as e:
            return {
                "synced": False,
                "error": str(e),
            }

    def get_config_schema(self) -> Dict[str, Any]:
        """Get JSON schema for OpenCTI configuration."""
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "title": "OpenCTI URL",
                    "description": "OpenCTI platform URL (e.g., https://opencti.example.com)",
                    "format": "uri",
                },
                "token": {
                    "type": "string",
                    "title": "API Token",
                    "description": "API bearer token (UUID)",
                    "format": "password",
                },
                "verify_ssl": {
                    "type": "boolean",
                    "title": "Verify SSL",
                    "description": "Whether to verify SSL certificates",
                    "default": True,
                },
            },
            "required": ["url", "token"],
        }

    def get_status_info(self) -> Dict[str, Any]:
        """Get OpenCTI connector status."""
        info = super().get_status_info()
        if self.is_configured:
            info["url"] = self._service.url
        return info
