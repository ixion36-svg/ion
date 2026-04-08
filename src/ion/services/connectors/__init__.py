"""Connector framework for integration management.

This package provides a unified interface for managing integrations with
external services like GitLab, OpenCTI, and Elasticsearch.
"""

from ion.services.connectors.base import (
    BaseConnector,
    ConnectorStatus,
    HealthCheckResult,
)
from ion.services.connectors.registry import (
    ConnectorRegistry,
    get_connector_registry,
    reset_connector_registry,
)
from ion.services.connectors.gitlab_connector import GitLabConnector
from ion.services.connectors.opencti_connector import OpenCTIConnector
from ion.services.connectors.elasticsearch_connector import ElasticsearchConnector
from ion.services.connectors.kibana_cases_connector import KibanaCasesConnector
from ion.services.connectors.tide_connector import TIDEConnector


def register_default_connectors() -> None:
    """Register all default connectors with the registry."""
    registry = get_connector_registry()
    registry.register_class("gitlab", GitLabConnector)
    registry.register_class("opencti", OpenCTIConnector)
    registry.register_class("elasticsearch", ElasticsearchConnector)
    registry.register_class("kibana_cases", KibanaCasesConnector)
    registry.register_class("tide", TIDEConnector)


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
    "KibanaCasesConnector",
    # Registration
    "register_default_connectors",
]
