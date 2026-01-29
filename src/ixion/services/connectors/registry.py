"""Connector registry for managing integration connectors.

Provides a singleton registry for registering and retrieving connectors.
"""

from typing import Dict, Type, Optional, List
import logging

from ixion.services.connectors.base import BaseConnector, HealthCheckResult

logger = logging.getLogger(__name__)


class ConnectorRegistry:
    """Singleton registry for integration connectors.

    Manages registration, retrieval, and lifecycle of connectors.
    """

    _instance: Optional["ConnectorRegistry"] = None
    _initialized: bool = False

    def __new__(cls) -> "ConnectorRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not ConnectorRegistry._initialized:
            self._connector_classes: Dict[str, Type[BaseConnector]] = {}
            self._connector_instances: Dict[str, BaseConnector] = {}
            ConnectorRegistry._initialized = True

    def register_class(
        self, connector_type: str, connector_class: Type[BaseConnector]
    ) -> None:
        """Register a connector class.

        Args:
            connector_type: Unique identifier for the connector type.
            connector_class: The connector class to register.
        """
        self._connector_classes[connector_type] = connector_class
        logger.debug("Registered connector class: %s", connector_type)

    def get(self, connector_type: str) -> Optional[BaseConnector]:
        """Get a connector instance by type.

        Creates the instance on first access (lazy initialization).

        Args:
            connector_type: The connector type to retrieve.

        Returns:
            The connector instance, or None if not registered.
        """
        if connector_type not in self._connector_classes:
            return None

        if connector_type not in self._connector_instances:
            connector_class = self._connector_classes[connector_type]
            self._connector_instances[connector_type] = connector_class()
            logger.debug("Created connector instance: %s", connector_type)

        return self._connector_instances[connector_type]

    def get_all(self) -> List[BaseConnector]:
        """Get all registered connector instances.

        Returns:
            List of all connector instances.
        """
        # Ensure all connectors are instantiated
        for connector_type in self._connector_classes:
            if connector_type not in self._connector_instances:
                self.get(connector_type)

        return list(self._connector_instances.values())

    def get_all_types(self) -> List[str]:
        """Get all registered connector types.

        Returns:
            List of connector type identifiers.
        """
        return list(self._connector_classes.keys())

    def reset(self, connector_type: str) -> None:
        """Reset a specific connector instance.

        Removes the cached instance so it will be recreated on next access.

        Args:
            connector_type: The connector type to reset.
        """
        if connector_type in self._connector_instances:
            del self._connector_instances[connector_type]
            logger.debug("Reset connector instance: %s", connector_type)

    def reset_all(self) -> None:
        """Reset all connector instances."""
        self._connector_instances.clear()
        logger.debug("Reset all connector instances")

    async def healthcheck_all(self) -> Dict[str, HealthCheckResult]:
        """Perform health checks on all connectors.

        Returns:
            Dictionary mapping connector types to health check results.
        """
        results = {}
        for connector_type in self._connector_classes:
            connector = self.get(connector_type)
            if connector:
                try:
                    results[connector_type] = await connector.healthcheck()
                except Exception as e:
                    logger.error(
                        "Health check failed for %s: %s", connector_type, e
                    )
                    from ixion.services.connectors.base import ConnectorStatus
                    results[connector_type] = HealthCheckResult(
                        status=ConnectorStatus.ERROR,
                        response_time_ms=0,
                        error=str(e),
                    )
        return results

    def get_status_all(self) -> Dict[str, Dict]:
        """Get status information for all connectors.

        Returns:
            Dictionary mapping connector types to status info.
        """
        status = {}
        for connector_type in self._connector_classes:
            connector = self.get(connector_type)
            if connector:
                status[connector_type] = connector.get_status_info()
        return status


# Global registry instance
_registry: Optional[ConnectorRegistry] = None


def get_connector_registry() -> ConnectorRegistry:
    """Get the global connector registry instance.

    Returns:
        The singleton ConnectorRegistry instance.
    """
    global _registry
    if _registry is None:
        _registry = ConnectorRegistry()
    return _registry


def reset_connector_registry() -> None:
    """Reset the global connector registry."""
    global _registry
    if _registry:
        _registry.reset_all()
    _registry = None
    ConnectorRegistry._instance = None
    ConnectorRegistry._initialized = False
