"""TIDE connector for integration management."""

from typing import Any, Dict

from ion.services.connectors.base import BaseConnector
from ion.services.tide_service import TideService, get_tide_service, reset_tide_service


class TIDEConnector(BaseConnector):
    """Connector for TIDE (Threat Informed Detection Engineering) integration."""

    CONNECTOR_TYPE = "tide"
    DISPLAY_NAME = "TIDE"

    def __init__(self):
        self._service: TideService = get_tide_service()

    @property
    def is_configured(self) -> bool:
        return self._service.enabled

    async def configure(self, config: Dict[str, Any]) -> bool:
        reset_tide_service()
        self._service = get_tide_service()
        return True

    async def test_connection(self) -> Dict[str, Any]:
        """Test the TIDE connection.

        Adapts TideService.test_connection() to the connector format
        expected by BaseConnector.healthcheck(). The service reports
        success as `ok`; the base class gates health on `connected`.
        Without this translation a reachable TIDE that answered the
        probe was still reported as ERROR "Connection failed" — the
        base class's fallback string, reached because the service's
        own `error` key is absent on the success path.
        """
        result = self._service.test_connection()
        return {
            "connected": result.get("ok", False),
            "rule_count": result.get("rule_count"),
            "space": result.get("space"),
            "error": result.get("error"),
        }

    async def sync(self, **kwargs) -> Dict[str, Any]:
        if not self.is_configured:
            return {"synced": False, "error": "TIDE is not configured"}
        result = self._service.test_connection()
        return {"synced": result.get("ok", False), "rule_count": result.get("rule_count", 0)}

    def get_config_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "title": "TIDE URL",
                    "description": "TIDE server URL (e.g., https://tide.example.com)",
                    "format": "uri",
                },
                "api_key": {
                    "type": "string",
                    "title": "API Key",
                    "description": "X-TIDE-API-KEY header value",
                    "format": "password",
                },
                "verify_ssl": {
                    "type": "boolean",
                    "title": "Verify SSL",
                    "description": "Whether to verify SSL certificates",
                    "default": False,
                },
            },
            "required": ["url", "api_key"],
        }

    def get_status_info(self) -> Dict[str, Any]:
        info = super().get_status_info()
        if self.is_configured:
            info["url"] = self._service.url
        return info
