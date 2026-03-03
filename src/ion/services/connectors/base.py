"""Base connector interface for integration management.

Defines the abstract interface that all integration connectors must implement.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Optional, TYPE_CHECKING
from enum import Enum

if TYPE_CHECKING:
    from ion.services.connectors.version_compat import VersionRange


class ConnectorStatus(str, Enum):
    """Status of a connector's health check."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    ERROR = "error"
    DISABLED = "disabled"
    NOT_CONFIGURED = "not_configured"


@dataclass
class HealthCheckResult:
    """Result of a connector health check."""
    status: ConnectorStatus
    response_time_ms: float
    message: Optional[str] = None
    error: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            "status": self.status.value,
            "response_time_ms": self.response_time_ms,
            "message": self.message,
            "error": self.error,
            "metadata": self.metadata,
        }


class BaseConnector(ABC):
    """Abstract base class for all integration connectors.

    Each connector wraps an existing service and provides a unified interface
    for configuration, health checking, and synchronization.
    """

    # Must be overridden by subclasses
    CONNECTOR_TYPE: str = "base"
    DISPLAY_NAME: str = "Base Connector"
    SUPPORTED_VERSIONS: Optional["VersionRange"] = None  # Override in subclasses
    VERSION_KEY: str = "version"  # Key in test_connection() result holding version string

    @property
    @abstractmethod
    def is_configured(self) -> bool:
        """Check if the connector has all required configuration."""
        pass

    @property
    def is_enabled(self) -> bool:
        """Check if the connector is enabled.

        By default, a connector is enabled if it is configured.
        Subclasses can override to add additional logic.
        """
        return self.is_configured

    @abstractmethod
    async def configure(self, config: Dict[str, Any]) -> bool:
        """Apply new configuration to the connector.

        Args:
            config: Configuration dictionary with connector-specific settings.

        Returns:
            True if configuration was applied successfully.
        """
        pass

    @abstractmethod
    async def test_connection(self) -> Dict[str, Any]:
        """Test the connection to the external service.

        Returns:
            Dictionary with connection status and details.
        """
        pass

    async def healthcheck(self) -> HealthCheckResult:
        """Perform a health check with timing.

        Returns:
            HealthCheckResult with status and response time.
        """
        import time

        if not self.is_configured:
            return HealthCheckResult(
                status=ConnectorStatus.NOT_CONFIGURED,
                response_time_ms=0,
                message="Connector is not configured",
            )

        start_time = time.perf_counter()
        try:
            result = await self.test_connection()
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            if result.get("connected"):
                status = ConnectorStatus.HEALTHY
                message = "Connection successful"
                metadata = dict(result)

                # Version compatibility check (if connector declares a range)
                if self.SUPPORTED_VERSIONS is not None:
                    from ion.services.connectors.version_compat import check_version_compatibility
                    detected = result.get(self.VERSION_KEY)
                    if detected:
                        compat = check_version_compatibility(detected, self.SUPPORTED_VERSIONS)
                        metadata["version_compatibility"] = compat
                        if not compat["in_range"]:
                            status = ConnectorStatus.DEGRADED
                            message = compat["message"]

                return HealthCheckResult(
                    status=status,
                    response_time_ms=elapsed_ms,
                    message=message,
                    metadata=metadata,
                )
            else:
                return HealthCheckResult(
                    status=ConnectorStatus.ERROR,
                    response_time_ms=elapsed_ms,
                    error=result.get("error", "Connection failed"),
                    metadata=result,
                )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return HealthCheckResult(
                status=ConnectorStatus.ERROR,
                response_time_ms=elapsed_ms,
                error=str(e),
            )

    async def sync(self, **kwargs) -> Dict[str, Any]:
        """Synchronize data with the external service.

        This is optional - not all connectors need synchronization.

        Args:
            **kwargs: Connector-specific synchronization options.

        Returns:
            Dictionary with sync results and statistics.
        """
        return {
            "synced": False,
            "message": "Sync not implemented for this connector",
        }

    def get_config_schema(self) -> Dict[str, Any]:
        """Get JSON schema for connector configuration.

        Returns:
            JSON Schema dictionary describing configuration fields.
        """
        return {
            "type": "object",
            "properties": {},
            "required": [],
        }

    def get_status_info(self) -> Dict[str, Any]:
        """Get current status information for the connector.

        Returns:
            Dictionary with status details.
        """
        return {
            "type": self.CONNECTOR_TYPE,
            "display_name": self.DISPLAY_NAME,
            "is_configured": self.is_configured,
            "is_enabled": self.is_enabled,
        }
