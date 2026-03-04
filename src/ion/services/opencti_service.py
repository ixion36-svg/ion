"""OpenCTI integration service for ION.

Provides IOC enrichment by querying OpenCTI's GraphQL API for observables,
indicators, and threat actors associated with given IOC values.
"""

from typing import Optional, Dict, Any, List
import logging
import httpx

from ion.core.config import get_opencti_config, get_ssl_verify

logger = logging.getLogger(__name__)


class OpenCTIError(Exception):
    """Exception raised for OpenCTI API errors."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class OpenCTIService:
    """Service for interacting with the OpenCTI GraphQL API."""

    # Map ION observable types to OpenCTI STIX types and filter keys
    TYPE_MAP = {
        "ipv4-addr": {"entity_type": "IPv4-Addr", "filter_key": "value"},
        "ipv6-addr": {"entity_type": "IPv6-Addr", "filter_key": "value"},
        "domain-name": {"entity_type": "Domain-Name", "filter_key": "value"},
        "url": {"entity_type": "Url", "filter_key": "value"},
        "file-sha256": {"entity_type": "StixFile", "filter_key": "hashes.SHA-256"},
        "file-sha1": {"entity_type": "StixFile", "filter_key": "hashes.SHA-1"},
        "file-md5": {"entity_type": "StixFile", "filter_key": "hashes.MD5"},
        "email-addr": {"entity_type": "Email-Addr", "filter_key": "value"},
        # Aliases for convenience
        "ip": {"entity_type": "IPv4-Addr", "filter_key": "value"},
        "domain": {"entity_type": "Domain-Name", "filter_key": "value"},
        "hostname": {"entity_type": "Domain-Name", "filter_key": "value"},
        "source_ip": {"entity_type": "IPv4-Addr", "filter_key": "value"},
        "destination_ip": {"entity_type": "IPv4-Addr", "filter_key": "value"},
    }

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
    ):
        """Initialize OpenCTI service.

        Args:
            url: OpenCTI platform URL (e.g., http://localhost:8888)
            token: API bearer token (UUID)
            verify_ssl: Whether to verify SSL certificates

        If not provided, values are loaded from configuration.
        """
        config = get_opencti_config()
        self.url = (url or config.get("url", "")).rstrip("/")
        self.token = token or config.get("token", "")
        self.verify_ssl = verify_ssl if verify_ssl is not None else config.get("verify_ssl", True)

    @property
    def is_configured(self) -> bool:
        """Check if OpenCTI integration is properly configured."""
        return bool(self.url) and bool(self.token)

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    async def _graphql(self, query: str, variables: Optional[Dict] = None) -> Dict:
        """Execute a GraphQL query against OpenCTI.

        Args:
            query: GraphQL query string
            variables: Optional query variables

        Returns:
            The 'data' portion of the GraphQL response.

        Raises:
            OpenCTIError: On network or GraphQL errors.
        """
        if not self.is_configured:
            raise OpenCTIError("OpenCTI integration is not configured")

        graphql_url = f"{self.url}/graphql"
        payload: Dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        try:
            async with httpx.AsyncClient(
                headers=self._get_headers(),
                verify=get_ssl_verify(self.verify_ssl),
                timeout=httpx.Timeout(30.0, connect=10.0),
            ) as client:
                response = await client.post(graphql_url, json=payload)
        except httpx.ConnectError as e:
            raise OpenCTIError(f"Failed to connect to OpenCTI: {e}")
        except httpx.ReadError as e:
            raise OpenCTIError(f"Connection error reading from OpenCTI: {e}")
        except httpx.TimeoutException as e:
            raise OpenCTIError(f"Request to OpenCTI timed out: {e}")
        except httpx.HTTPError as e:
            raise OpenCTIError(f"HTTP error communicating with OpenCTI: {e}")

        if response.status_code >= 400:
            try:
                error_data = response.json()
                error_msg = str(error_data.get("errors", error_data))
            except Exception:
                error_msg = response.text
            raise OpenCTIError(
                f"OpenCTI API error: {error_msg}", response.status_code
            )

        result = response.json()
        if "errors" in result:
            errors = result["errors"]
            msg = "; ".join(e.get("message", str(e)) for e in errors)
            raise OpenCTIError(f"OpenCTI GraphQL error: {msg}")

        return result.get("data", {})

    async def test_connection(self) -> Dict[str, Any]:
        """Test the OpenCTI connection.

        Returns:
            Dict with connection status and user info.
        """
        if not self.is_configured:
            return {
                "connected": False,
                "error": "OpenCTI integration is not configured",
            }

        try:
            data = await self._graphql("{ me { name user_email } }")
            me = data.get("me", {})
            return {
                "connected": True,
                "user_name": me.get("name"),
                "user_email": me.get("user_email"),
            }
        except OpenCTIError as e:
            return {
                "connected": False,
                "error": str(e),
            }

    async def enrich_observable(
        self, obs_type: str, obs_value: str
    ) -> Dict[str, Any]:
        """Enrich a single observable by querying OpenCTI.

        Args:
            obs_type: Observable type (e.g., "ipv4-addr", "domain-name",
                      "file-sha256", "url", or ION aliases like "source_ip")
            obs_value: The observable value to look up

        Returns:
            Dict with enrichment results:
            {
                "found": bool,
                "type": str,
                "value": str,
                "observable": {...} | None,
                "indicators": [...],
                "threat_actors": [...],
                "labels": [...],
                "reports": [...],
                "error": str | None
            }
        """
        result = {
            "found": False,
            "type": obs_type,
            "value": obs_value,
            "observable": None,
            "indicators": [],
            "threat_actors": [],
            "labels": [],
            "reports": [],
            "error": None,
        }

        if not self.is_configured:
            result["error"] = "OpenCTI integration is not configured"
            return result

        type_info = self.TYPE_MAP.get(obs_type)
        if not type_info:
            result["error"] = f"Unsupported observable type: {obs_type}"
            return result

        try:
            # Query for the observable and its related entities
            query = """
            query EnrichObservable($filters: FilterGroup) {
                stixCyberObservables(filters: $filters, first: 1) {
                    edges {
                        node {
                            id
                            entity_type
                            observable_value
                            x_opencti_description
                            x_opencti_score
                            objectLabel {
                                id
                                value
                                color
                            }
                            createdBy {
                                name
                            }
                            indicators {
                                edges {
                                    node {
                                        id
                                        name
                                        description
                                        pattern
                                        indicator_types
                                        valid_from
                                        valid_until
                                        x_opencti_score
                                        objectLabel {
                                            id
                                            value
                                            color
                                        }
                                    }
                                }
                            }
                            reports {
                                edges {
                                    node {
                                        id
                                        name
                                        description
                                        published
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """

            # Build filter for the observable value
            filters = {
                "mode": "and",
                "filters": [
                    {
                        "key": type_info["filter_key"],
                        "values": [obs_value],
                        "operator": "eq",
                        "mode": "or",
                    }
                ],
                "filterGroups": [],
            }

            data = await self._graphql(query, {"filters": filters})

            edges = (
                data.get("stixCyberObservables", {}).get("edges", [])
            )

            if not edges:
                # Also try querying indicators by pattern for a broader match
                indicator_results = await self._search_indicators(obs_type, obs_value)
                if indicator_results:
                    result["found"] = True
                    result["indicators"] = indicator_results["indicators"]
                    result["threat_actors"] = indicator_results.get("threat_actors", [])
                    result["labels"] = indicator_results.get("labels", [])
                return result

            node = edges[0]["node"]
            result["found"] = True

            # Parse observable info
            result["observable"] = {
                "id": node.get("id"),
                "type": node.get("entity_type"),
                "value": node.get("observable_value"),
                "description": node.get("x_opencti_description"),
                "score": node.get("x_opencti_score"),
                "created_by": (node.get("createdBy") or {}).get("name"),
            }

            # Parse labels
            for label in node.get("objectLabel", []) or []:
                result["labels"].append({
                    "value": label.get("value"),
                    "color": label.get("color"),
                })

            # Parse indicators
            for edge in (node.get("indicators", {}) or {}).get("edges", []):
                ind = edge.get("node", {})
                indicator_labels = [
                    {"value": l.get("value"), "color": l.get("color")}
                    for l in (ind.get("objectLabel") or [])
                ]
                result["indicators"].append({
                    "id": ind.get("id"),
                    "name": ind.get("name"),
                    "description": ind.get("description"),
                    "pattern": ind.get("pattern"),
                    "indicator_types": ind.get("indicator_types", []),
                    "valid_from": ind.get("valid_from"),
                    "valid_until": ind.get("valid_until"),
                    "score": ind.get("x_opencti_score"),
                    "labels": indicator_labels,
                })

            # Look for threat actors linked through indicators
            await self._enrich_threat_actors_from_indicators(result)

            # Parse reports
            for edge in (node.get("reports", {}) or {}).get("edges", []):
                rpt = edge.get("node", {})
                result["reports"].append({
                    "id": rpt.get("id"),
                    "name": rpt.get("name"),
                    "description": rpt.get("description"),
                    "published": rpt.get("published"),
                })

        except OpenCTIError as e:
            result["error"] = str(e)
            logger.warning("OpenCTI enrichment failed for %s=%s: %s", obs_type, obs_value, e)

        return result

    async def _search_indicators(
        self, obs_type: str, obs_value: str
    ) -> Optional[Dict]:
        """Search for indicators matching the observable value by pattern."""
        try:
            # Search indicators whose pattern contains the value
            query = """
            query SearchIndicators($search: String) {
                indicators(search: $search, first: 5) {
                    edges {
                        node {
                            id
                            name
                            description
                            pattern
                            indicator_types
                            valid_from
                            valid_until
                            x_opencti_score
                            objectLabel {
                                id
                                value
                                color
                            }
                        }
                    }
                }
            }
            """
            data = await self._graphql(query, {"search": obs_value})
            edges = data.get("indicators", {}).get("edges", [])
            if not edges:
                return None

            indicators = []
            labels = []
            for edge in edges:
                ind = edge.get("node", {})
                ind_labels = [
                    {"value": l.get("value"), "color": l.get("color")}
                    for l in (ind.get("objectLabel") or [])
                ]
                indicators.append({
                    "id": ind.get("id"),
                    "name": ind.get("name"),
                    "description": ind.get("description"),
                    "pattern": ind.get("pattern"),
                    "indicator_types": ind.get("indicator_types", []),
                    "valid_from": ind.get("valid_from"),
                    "valid_until": ind.get("valid_until"),
                    "score": ind.get("x_opencti_score"),
                    "labels": ind_labels,
                })
                labels.extend(ind_labels)

            # Deduplicate labels
            seen_labels = set()
            unique_labels = []
            for lbl in labels:
                key = lbl.get("value", "")
                if key not in seen_labels:
                    seen_labels.add(key)
                    unique_labels.append(lbl)

            return {
                "indicators": indicators,
                "labels": unique_labels,
                "threat_actors": [],
            }
        except OpenCTIError:
            return None

    async def _enrich_threat_actors_from_indicators(
        self, result: Dict
    ) -> None:
        """Find threat actors linked to the indicators already found."""
        if not result["indicators"]:
            return

        indicator_ids = [
            ind["id"] for ind in result["indicators"] if ind.get("id")
        ]
        if not indicator_ids:
            return

        existing_actor_ids = {
            ta["id"] for ta in result["threat_actors"] if ta.get("id")
        }

        try:
            # Query relationships where our indicators point to threat actors
            query = """
            query RelsByIndicators($filters: FilterGroup) {
                stixCoreRelationships(filters: $filters, first: 20) {
                    edges {
                        node {
                            relationship_type
                            to {
                                ... on ThreatActorGroup {
                                    id
                                    name
                                    description
                                    threat_actor_types
                                }
                                ... on ThreatActorIndividual {
                                    id
                                    name
                                    description
                                    threat_actor_types
                                }
                            }
                        }
                    }
                }
            }
            """
            filters = {
                "mode": "and",
                "filters": [
                    {
                        "key": "fromId",
                        "values": indicator_ids,
                        "operator": "eq",
                        "mode": "or",
                    },
                    {
                        "key": "relationship_type",
                        "values": ["indicates"],
                        "operator": "eq",
                        "mode": "or",
                    },
                ],
                "filterGroups": [],
            }
            data = await self._graphql(query, {"filters": filters})
            edges = data.get("stixCoreRelationships", {}).get("edges", [])
            for edge in edges:
                rel = edge.get("node", {})
                target = rel.get("to") or {}
                if target.get("id") and target["id"] not in existing_actor_ids:
                    result["threat_actors"].append({
                        "id": target["id"],
                        "name": target.get("name"),
                        "description": target.get("description"),
                        "types": target.get("threat_actor_types", []),
                        "relationship": rel.get("relationship_type"),
                    })
                    existing_actor_ids.add(target["id"])
        except OpenCTIError as e:
            logger.debug("Threat actor enrichment query failed: %s", e)

    async def enrich_batch(
        self, observables: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        """Enrich multiple observables.

        Args:
            observables: List of dicts with 'type' and 'value' keys.
                Example: [{"type": "ipv4-addr", "value": "1.2.3.4"}, ...]

        Returns:
            List of enrichment result dicts (same format as enrich_observable).
        """
        results = []
        for obs in observables:
            obs_type = obs.get("type", "")
            obs_value = obs.get("value", "")
            if not obs_type or not obs_value:
                results.append({
                    "found": False,
                    "type": obs_type,
                    "value": obs_value,
                    "observable": None,
                    "indicators": [],
                    "threat_actors": [],
                    "labels": [],
                    "reports": [],
                    "error": "Missing type or value",
                })
                continue
            result = await self.enrich_observable(obs_type, obs_value)
            results.append(result)
        return results


# Singleton instance
_opencti_service: Optional[OpenCTIService] = None


def get_opencti_service() -> OpenCTIService:
    """Get the global OpenCTI service instance."""
    global _opencti_service
    if _opencti_service is None:
        _opencti_service = OpenCTIService()
    return _opencti_service


def reset_opencti_service():
    """Reset the global OpenCTI service instance (for config changes)."""
    global _opencti_service
    _opencti_service = None
