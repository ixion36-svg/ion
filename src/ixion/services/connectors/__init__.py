"""Connector framework for integration management.

This package provides a unified interface for managing integrations with
external services like GitLab, OpenCTI, and Elasticsearch.
"""

from ixion.services.connectors.base import (
    BaseConnector,
    ConnectorStatus,
    HealthCheckResult,
)
from ixion.services.connectors.registry import (
    ConnectorRegistry,
    get_connector_registry,
    reset_connector_registry,
)
from ixion.services.connectors.gitlab_connector import GitLabConnector
from ixion.services.connectors.opencti_connector import OpenCTIConnector
from ixion.services.connectors.elasticsearch_connector import ElasticsearchConnector


def register_default_connectors() -> None:
    """Register all default connectors with the registry."""
    registry = get_connector_registry()
    registry.register_class("gitlab", GitLabConnector)
    registry.register_class("opencti", OpenCTIConnector)
    registry.register_class("elasticsearch", ElasticsearchConnector)


# Auto-register connectors on import
register_default_connectors()


__all__ = [
    # Base classes
    "BaseConnector",
    "ConnectorStatus",
    "HealthCheckResult",
    # Registry
    "ConnectorRegistry",
    "get_connector_registry",
    "reset_connector_registry",
    # Connectors
    "GitLabConnector",
    "OpenCTIConnector",
    "ElasticsearchConnector",
    # Registration
    "register_default_connectors",
]
