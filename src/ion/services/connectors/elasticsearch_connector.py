"""Elasticsearch connector for integration management.

Wraps the ElasticsearchService to provide a unified connector interface.
"""

from typing import Dict, Any, Optional

from ion.services.connectors.base import BaseConnector
from ion.services.connectors.version_compat import ELASTICSEARCH_VERSIONS
from ion.services.elasticsearch_service import ElasticsearchService


# Singleton for elasticsearch service
_elasticsearch_service: Optional[ElasticsearchService] = None


def get_elasticsearch_service() -> ElasticsearchService:
    """Get the global Elasticsearch service instance."""
    global _elasticsearch_service
    if _elasticsearch_service is None:
        _elasticsearch_service = ElasticsearchService()
    return _elasticsearch_service


def reset_elasticsearch_service():
    """Reset the global Elasticsearch service instance."""
    global _elasticsearch_service
    _elasticsearch_service = None


class ElasticsearchConnector(BaseConnector):
    """Connector for Elasticsearch integration."""

    CONNECTOR_TYPE = "elasticsearch"
    DISPLAY_NAME = "Elasticsearch"
    SUPPORTED_VERSIONS = ELASTICSEARCH_VERSIONS
    VERSION_KEY = "version"

    def __init__(self):
        self._service: ElasticsearchService = get_elasticsearch_service()

    @property
    def is_configured(self) -> bool:
        """Check if Elasticsearch is configured."""
        return self._service.is_configured

    async def configure(self, config: Dict[str, Any]) -> bool:
        """Apply new configuration to the Elasticsearch service.

        Args:
            config: Configuration with connection settings.

        Returns:
            True if configuration was applied successfully.
        """
        # Reset the service to pick up new configuration
        reset_elasticsearch_service()
        self._service = get_elasticsearch_service()
        return True

    async def test_connection(self) -> Dict[str, Any]:
        """Test the Elasticsearch connection."""
        return await self._service.test_connection()

    async def sync(self, **kwargs) -> Dict[str, Any]:
        """Fetch alerts from Elasticsearch.

        Args:
            **kwargs: Optional filters (hours, severity, status, limit).

        Returns:
            Dictionary with fetched alerts.
        """
        if not self.is_configured:
            return {
                "synced": False,
                "error": "Elasticsearch is not configured",
            }

        try:
            alerts = await self._service.get_alerts(
                hours=kwargs.get("hours", 24),
                severity=kwargs.get("severity"),
                status=kwargs.get("status"),
                limit=kwargs.get("limit", 50),
            )
            return {
                "synced": True,
                "alerts_count": len(alerts),
                "alerts": [alert.to_dict() for alert in alerts],
            }
        except Exception as e:
            return {
                "synced": False,
                "error": str(e),
            }

    def get_config_schema(self) -> Dict[str, Any]:
        """Get JSON schema for Elasticsearch configuration."""
        return {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "title": "Elasticsearch URL",
                    "description": "Elasticsearch cluster URL (e.g., https://localhost:9200)",
                    "format": "uri",
                },
                "api_key": {
                    "type": "string",
                    "title": "API Key",
                    "description": "Elasticsearch API key (preferred authentication method)",
                    "format": "password",
                },
                "username": {
                    "type": "string",
                    "title": "Username",
                    "description": "Basic auth username (alternative to API key)",
                },
                "password": {
                    "type": "string",
                    "title": "Password",
                    "description": "Basic auth password",
                    "format": "password",
                },
                "alert_index": {
                    "type": "string",
                    "title": "Alert Index Pattern",
                    "description": "Index pattern for alerts (e.g., .alerts-*,.watcher-history-*)",
                    "default": ".alerts-*,.watcher-history-*,alerts-*",
                },
                "case_index": {
                    "type": "string",
                    "title": "Case Index",
                    "description": "Index for case documents",
                    "default": "ion-cases",
                },
                "verify_ssl": {
                    "type": "boolean",
                    "title": "Verify SSL",
                    "description": "Whether to verify SSL certificates",
                    "default": True,
                },
            },
            "required": ["url"],
        }

    def get_status_info(self) -> Dict[str, Any]:
        """Get Elasticsearch connector status."""
        info = super().get_status_info()
        if self.is_configured:
            info["url"] = self._service.url
            info["alert_index"] = self._service.alert_index
        return info
