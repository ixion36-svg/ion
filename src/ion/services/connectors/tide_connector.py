"""TIDE connector for integration management."""

from typing import Dict, Any

from ion.services.connectors.base import BaseConnector
from ion.services.tide_service import get_tide_service, reset_tide_service, TideService


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
        return self._service.test_connection()

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
