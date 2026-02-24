"""Elasticsearch integration service for IXION.

Provides functionality to fetch alerts and security events from Elasticsearch.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging
import httpx

from ixion.core.config import get_elasticsearch_config

logger = logging.getLogger(__name__)


@dataclass
class ElasticsearchAlert:
    """Represents an alert from Elasticsearch."""

    id: str
    title: str
    severity: str  # critical, high, medium, low, info
    status: str  # open, acknowledged, resolved
    source: str  # e.g., "watcher", "siem", "custom"
    message: str
    timestamp: datetime
    rule_name: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None
    tags: List[str] = None
    raw_data: Dict[str, Any] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    mitre_tactic_name: Optional[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.raw_data is None:
            self.raw_data = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "source": self.source,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "rule_name": self.rule_name,
            "host": self.host,
            "user": self.user,
            "tags": self.tags,
            "raw_data": self.raw_data,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "mitre_tactic_name": self.mitre_tactic_name,
        }


class ElasticsearchError(Exception):
    """Exception raised for Elasticsearch errors."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class ElasticsearchService:
    """Service for interacting with Elasticsearch."""

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        alert_index: Optional[str] = None,
        case_index: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        """Initialize Elasticsearch service.

        Args:
            url: Elasticsearch URL (e.g., https://localhost:9200)
            api_key: API key for authentication (preferred)
            username: Basic auth username
            password: Basic auth password
            alert_index: Index pattern for alerts (e.g., ".alerts-*" or "alerts-*")
            case_index: Index for synced case documents
            verify_ssl: Whether to verify SSL certificates
        """
        config = get_elasticsearch_config()
        self.url = (url or config.get("url", "")).rstrip("/")
        self.api_key = api_key or config.get("api_key", "")
        self.username = username or config.get("username", "")
        self.password = password or config.get("password", "")
        self.alert_index = alert_index or config.get("alert_index", ".alerts-*,.watcher-history-*,alerts-*")
        self.case_index = case_index or config.get("case_index", "ixion-cases")
        self.kfp_index = config.get("kfp_index", "ixion-kfp")
        self.verify_ssl = verify_ssl if verify_ssl is not None else config.get("verify_ssl", True)

    @property
    def is_configured(self) -> bool:
        """Check if Elasticsearch integration is properly configured."""
        has_auth = bool(self.api_key) or (bool(self.username) and bool(self.password))
        return bool(self.url) and has_auth

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication."""
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        return headers

    def _get_auth(self) -> Optional[tuple]:
        """Get basic auth tuple if using username/password."""
        if not self.api_key and self.username and self.password:
            return (self.username, self.password)
        return None

    async def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs,
    ) -> Any:
        """Make an authenticated request to Elasticsearch."""
        if not self.is_configured:
            raise ElasticsearchError("Elasticsearch integration is not configured")

        url = f"{self.url}/{endpoint.lstrip('/')}"

        # For search requests on multi-index patterns, skip missing indices
        if "/_search" in endpoint:
            sep = "&" if "?" in url else "?"
            url += f"{sep}ignore_unavailable=true&allow_no_indices=true"

        try:
            async with httpx.AsyncClient(
                headers=self._get_headers(),
                auth=self._get_auth(),
                verify=self.verify_ssl,
                timeout=httpx.Timeout(30.0, connect=10.0),
            ) as client:
                response = await client.request(method, url, **kwargs)
        except httpx.ConnectError as e:
            raise ElasticsearchError(f"Failed to connect to Elasticsearch: {e}")
        except httpx.ReadError as e:
            raise ElasticsearchError(f"Connection error reading from Elasticsearch: {e}")
        except httpx.TimeoutException as e:
            raise ElasticsearchError(f"Request to Elasticsearch timed out: {e}")
        except httpx.HTTPError as e:
            raise ElasticsearchError(f"HTTP error communicating with Elasticsearch: {e}")

        if response.status_code >= 400:
            try:
                error_data = response.json()
                error_msg = error_data.get("error", {})
                if isinstance(error_msg, dict):
                    error_msg = error_msg.get("reason", str(error_data))
                else:
                    error_msg = str(error_msg)
            except Exception:
                error_msg = response.text
            raise ElasticsearchError(f"Elasticsearch error: {error_msg}", response.status_code)

        return response.json()

    async def test_connection(self) -> Dict[str, Any]:
        """Test the Elasticsearch connection."""
        if not self.is_configured:
            return {
                "connected": False,
                "error": "Elasticsearch integration is not configured",
            }

        try:
            info = await self._request("GET", "/")
            return {
                "connected": True,
                "cluster_name": info.get("cluster_name"),
                "version": info.get("version", {}).get("number"),
            }
        except ElasticsearchError as e:
            return {
                "connected": False,
                "error": str(e),
            }

    async def get_alerts(
        self,
        hours: int = 24,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[ElasticsearchAlert]:
        """Fetch alerts from Elasticsearch.

        Args:
            hours: Number of hours to look back
            severity: Filter by severity (critical, high, medium, low, info)
            status: Filter by status (open, acknowledged, resolved)
            limit: Maximum number of alerts to return
        """
        # Build query
        must_clauses = [
            {
                "range": {
                    "@timestamp": {
                        "gte": f"now-{hours}h",
                        "lte": "now"
                    }
                }
            }
        ]

        if severity:
            must_clauses.append({
                "bool": {
                    "should": [
                        {"term": {"event.severity": severity}},
                        {"term": {"kibana.alert.severity": severity}},
                        {"term": {"signal.rule.severity": severity}},
                        {"term": {"severity": severity}},
                    ],
                    "minimum_should_match": 1
                }
            })

        if status:
            must_clauses.append({
                "bool": {
                    "should": [
                        {"term": {"kibana.alert.status": status}},
                        {"term": {"status": status}},
                        {"term": {"state": status}},
                    ],
                    "minimum_should_match": 1
                }
            })

        query = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": must_clauses
                }
            }
        }

        try:
            result = await self._request(
                "POST",
                f"/{self.alert_index}/_search",
                json=query,
            )
        except ElasticsearchError as e:
            # If index doesn't exist, return empty list
            if "index_not_found" in str(e).lower() or "404" in str(e):
                return []
            raise

        alerts = []
        for hit in result.get("hits", {}).get("hits", []):
            source = hit.get("_source", {})
            alert = self._parse_alert(hit["_id"], source)
            if alert:
                alerts.append(alert)

        return alerts

    async def get_alerts_by_ids(self, alert_ids: List[str]) -> List[ElasticsearchAlert]:
        """Fetch multiple alerts by their document IDs."""
        if not alert_ids:
            return []

        query = {
            "size": len(alert_ids),
            "query": {"ids": {"values": alert_ids}},
        }
        try:
            result = await self._request(
                "POST",
                f"/{self.alert_index}/_search",
                json=query,
            )
        except ElasticsearchError:
            return []

        alerts = []
        for hit in result.get("hits", {}).get("hits", []):
            alert = self._parse_alert(hit["_id"], hit.get("_source", {}))
            if alert:
                alerts.append(alert)
        return alerts

    def _parse_alert(self, alert_id: str, source: Dict[str, Any]) -> Optional[ElasticsearchAlert]:
        """Parse an alert from various Elasticsearch formats."""
        # Try to extract common fields from different alert formats
        # Supports: Elastic Security (SIEM), Watcher, and custom formats

        # Timestamp
        timestamp_str = (
            source.get("@timestamp") or
            source.get("timestamp") or
            source.get("kibana.alert.start") or
            datetime.utcnow().isoformat()
        )
        try:
            if isinstance(timestamp_str, str):
                # Handle various timestamp formats
                timestamp_str = timestamp_str.replace("Z", "+00:00")
                if "." in timestamp_str and "+" in timestamp_str:
                    # Truncate microseconds if too long
                    parts = timestamp_str.split("+")
                    timestamp_str = parts[0][:26] + "+" + parts[1]
                timestamp = datetime.fromisoformat(timestamp_str)
            else:
                timestamp = datetime.utcnow()
        except (ValueError, TypeError):
            timestamp = datetime.utcnow()

        # Title - try multiple fields
        title = (
            source.get("kibana.alert.rule.name") or
            source.get("signal", {}).get("rule", {}).get("name") or
            source.get("rule", {}).get("name") or
            source.get("alert_type") or
            source.get("event", {}).get("action") or
            source.get("message", "")[:100] or
            "Unknown Alert"
        )

        # Severity
        severity = (
            source.get("kibana.alert.severity") or
            source.get("event", {}).get("severity") or
            source.get("signal", {}).get("rule", {}).get("severity") or
            source.get("severity") or
            source.get("level") or
            "medium"
        )
        # Normalize severity
        severity_map = {
            "1": "critical", "critical": "critical", "crit": "critical",
            "2": "high", "high": "high",
            "3": "medium", "medium": "medium", "med": "medium", "warning": "medium",
            "4": "low", "low": "low",
            "5": "info", "info": "info", "informational": "info",
        }
        severity = severity_map.get(str(severity).lower(), "medium")

        # Status
        status = (
            source.get("kibana.alert.status") or
            source.get("status") or
            source.get("state") or
            "open"
        )
        status_map = {
            "active": "open", "open": "open", "new": "open", "triggered": "open",
            "acknowledged": "acknowledged", "acked": "acknowledged", "in_progress": "acknowledged",
            "resolved": "resolved", "closed": "resolved", "ok": "resolved",
        }
        status = status_map.get(str(status).lower(), "open")

        # Source type
        alert_source = "custom"
        if "kibana.alert" in str(source):
            alert_source = "siem"
        elif "watcher" in str(source) or source.get("watch_id"):
            alert_source = "watcher"
        elif source.get("signal"):
            alert_source = "siem"

        # Message
        message = (
            source.get("message") or
            source.get("kibana.alert.reason") or
            source.get("signal", {}).get("rule", {}).get("description") or
            source.get("rule", {}).get("description") or
            title
        )

        # Host
        host = (
            source.get("host", {}).get("name") or
            source.get("host", {}).get("hostname") or
            source.get("agent", {}).get("hostname") or
            source.get("hostname")
        )
        if isinstance(host, dict):
            host = host.get("name")

        # User
        user = (
            source.get("user", {}).get("name") or
            source.get("user_name") or
            source.get("winlog", {}).get("user", {}).get("name")
        )
        if isinstance(user, dict):
            user = user.get("name")

        # Tags
        tags = source.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        # Rule name
        rule_name = (
            source.get("kibana.alert.rule.name") or
            source.get("signal", {}).get("rule", {}).get("name") or
            source.get("rule", {}).get("name") or
            source.get("rule_name")
        )

        # MITRE ATT&CK fields
        # Helper to unwrap list-or-scalar values (ES may store as ["Impact"] or "Impact")
        def _first(val):
            if isinstance(val, list) and val:
                return val[0]
            return val

        # Primary path: nested threat object (ECS format)
        threat = source.get("threat", {})
        mitre_technique_id = None
        mitre_technique_name = None
        mitre_tactic_name = None

        if isinstance(threat, dict) and threat:
            technique = threat.get("technique", {})
            tactic = threat.get("tactic", {})
            if isinstance(technique, dict):
                mitre_technique_id = _first(technique.get("id"))
                mitre_technique_name = _first(technique.get("name"))
            elif isinstance(technique, list) and technique:
                mitre_technique_id = _first(technique[0].get("id"))
                mitre_technique_name = _first(technique[0].get("name"))
            if isinstance(tactic, dict):
                mitre_tactic_name = _first(tactic.get("name"))
            elif isinstance(tactic, list) and tactic:
                mitre_tactic_name = _first(tactic[0].get("name"))

        # Fallback: dot-notation keys (Kibana Security alert format)
        if not mitre_technique_id:
            mitre_technique_id = _first(source.get("threat.technique.id"))
        if not mitre_technique_name:
            mitre_technique_name = _first(source.get("threat.technique.name"))
        if not mitre_tactic_name:
            mitre_tactic_name = _first(source.get("threat.tactic.name"))

        # Fallback: signal.rule.threat[0].technique[0] (Elastic SIEM format)
        if not mitre_technique_id:
            signal_threats = source.get("signal", {}).get("rule", {}).get("threat", [])
            if isinstance(signal_threats, list) and signal_threats:
                first_threat = signal_threats[0]
                if isinstance(first_threat, dict):
                    techniques = first_threat.get("technique", [])
                    if isinstance(techniques, list) and techniques:
                        mitre_technique_id = _first(techniques[0].get("id"))
                        mitre_technique_name = _first(techniques[0].get("name"))
                    tactic_obj = first_threat.get("tactic", {})
                    if isinstance(tactic_obj, dict):
                        mitre_tactic_name = _first(tactic_obj.get("name"))

        return ElasticsearchAlert(
            id=alert_id,
            title=title,
            severity=severity,
            status=status,
            source=alert_source,
            message=message,
            timestamp=timestamp,
            rule_name=rule_name,
            host=host,
            user=user,
            tags=tags,
            raw_data=source,
            mitre_technique_id=mitre_technique_id,
            mitre_technique_name=mitre_technique_name,
            mitre_tactic_name=mitre_tactic_name,
        )

    async def get_related_alerts(
        self,
        alert_id: str,
        host: Optional[str] = None,
        user: Optional[str] = None,
        rule_name: Optional[str] = None,
        hours: int = 72,
        limit: int = 20,
    ) -> Dict[str, List[ElasticsearchAlert]]:
        """Find alerts related to a given alert by shared host, user, or rule.

        Returns a dict with keys 'by_host', 'by_user', 'by_rule' each containing
        a list of related alerts (excluding the original alert).
        """
        related = {}

        async def search_by_field(field_queries: List[Dict], label: str):
            query = {
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": f"now-{hours}h",
                                        "lte": "now"
                                    }
                                }
                            },
                            {
                                "bool": {
                                    "should": field_queries,
                                    "minimum_should_match": 1
                                }
                            }
                        ],
                        "must_not": [
                            {"ids": {"values": [alert_id]}}
                        ]
                    }
                }
            }
            try:
                result = await self._request(
                    "POST",
                    f"/{self.alert_index}/_search",
                    json=query,
                )
                alerts = []
                for hit in result.get("hits", {}).get("hits", []):
                    source = hit.get("_source", {})
                    alert = self._parse_alert(hit["_id"], source)
                    if alert:
                        alerts.append(alert)
                return alerts
            except ElasticsearchError:
                return []

        if host:
            related["by_host"] = await search_by_field([
                {"term": {"host.name": host}},
                {"term": {"host.hostname": host}},
                {"term": {"agent.hostname": host}},
                {"term": {"hostname": host}},
            ], "host")

        if user:
            related["by_user"] = await search_by_field([
                {"term": {"user.name": user}},
                {"term": {"user_name": user}},
            ], "user")

        if rule_name:
            related["by_rule"] = await search_by_field([
                {"term": {"kibana.alert.rule.name.keyword": rule_name}},
                {"term": {"rule.name.keyword": rule_name}},
                {"match_phrase": {"kibana.alert.rule.name": rule_name}},
                {"match_phrase": {"rule.name": rule_name}},
            ], "rule")

        return related

    async def get_alerts_by_ids(
        self,
        alert_ids: List[str],
        index: Optional[str] = None,
    ) -> List[ElasticsearchAlert]:
        """Fetch specific alerts by their IDs.

        Args:
            alert_ids: List of alert IDs to fetch
            index: Optional index to search (defaults to configured alert_index)

        Returns:
            List of ElasticsearchAlert objects
        """
        if not alert_ids:
            return []

        search_index = index or self.alert_index

        query = {
            "size": len(alert_ids),
            "query": {
                "ids": {
                    "values": alert_ids
                }
            }
        }

        try:
            result = await self._request(
                "POST",
                f"/{search_index}/_search",
                json=query,
            )
        except ElasticsearchError as e:
            logger.error(f"Error fetching alerts by ID: {e}")
            return []

        alerts = []
        for hit in result.get("hits", {}).get("hits", []):
            source = hit.get("_source", {})
            alert = self._parse_alert(hit["_id"], source)
            if alert:
                # Include raw_data for observable extraction
                alert.raw_data = source
                alerts.append(alert)

        return alerts

    async def get_alert_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get alert statistics."""
        query = {
            "size": 0,
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": f"now-{hours}h",
                        "lte": "now"
                    }
                }
            },
            "aggs": {
                "by_severity": {
                    "terms": {
                        "field": "event.severity",
                        "missing": "unknown"
                    }
                },
                "by_status": {
                    "terms": {
                        "field": "kibana.alert.status",
                        "missing": "unknown"
                    }
                }
            }
        }

        try:
            result = await self._request(
                "POST",
                f"/{self.alert_index}/_search",
                json=query,
            )
        except ElasticsearchError as e:
            if "index_not_found" in str(e).lower():
                return {
                    "total": 0,
                    "by_severity": {},
                    "by_status": {},
                }
            raise

        total = result.get("hits", {}).get("total", {})
        if isinstance(total, dict):
            total = total.get("value", 0)

        severity_buckets = result.get("aggregations", {}).get("by_severity", {}).get("buckets", [])
        status_buckets = result.get("aggregations", {}).get("by_status", {}).get("buckets", [])

        return {
            "total": total,
            "by_severity": {b["key"]: b["doc_count"] for b in severity_buckets},
            "by_status": {b["key"]: b["doc_count"] for b in status_buckets},
        }

    async def index_case(self, case_doc: dict) -> bool:
        """Index (upsert) a case document into Elasticsearch.

        Args:
            case_doc: Full case document dict. Must contain an 'id' key used as the ES document ID.

        Returns:
            True on success, False on failure (logs warning, does not raise).
        """
        case_id = case_doc.get("id")
        if case_id is None:
            logger.warning("index_case called without 'id' in case_doc")
            return False

        try:
            await self._request(
                "PUT",
                f"/{self.case_index}/_doc/{case_id}",
                json=case_doc,
            )
            return True
        except Exception as e:
            logger.warning("Failed to index case %s to Elasticsearch: %s", case_id, e)
            return False

    async def delete_case(self, case_id: int) -> bool:
        """Delete a case document from Elasticsearch.

        Args:
            case_id: The case ID (used as the ES document ID).

        Returns:
            True on success, False on failure (logs warning, does not raise).
        """
        try:
            await self._request(
                "DELETE",
                f"/{self.case_index}/_doc/{case_id}",
            )
            return True
        except Exception as e:
            logger.warning("Failed to delete case %s from Elasticsearch: %s", case_id, e)
            return False

    async def index_kfp(self, kfp_doc: dict) -> bool:
        """Index (upsert) a known false positive document into Elasticsearch.

        Args:
            kfp_doc: Full KFP document dict. Must contain an 'id' key.

        Returns:
            True on success, False on failure (logs warning, does not raise).
        """
        kfp_id = kfp_doc.get("id")
        if kfp_id is None:
            logger.warning("index_kfp called without 'id' in kfp_doc")
            return False

        try:
            await self._request(
                "PUT",
                f"/{self.kfp_index}/_doc/{kfp_id}",
                json=kfp_doc,
            )
            return True
        except Exception as e:
            logger.warning("Failed to index KFP %s to Elasticsearch: %s", kfp_id, e)
            return False

    async def delete_kfp(self, kfp_id: int) -> bool:
        """Delete a KFP document from Elasticsearch.

        Args:
            kfp_id: The KFP ID (used as the ES document ID).

        Returns:
            True on success, False on failure (logs warning, does not raise).
        """
        try:
            await self._request(
                "DELETE",
                f"/{self.kfp_index}/_doc/{kfp_id}",
            )
            return True
        except Exception as e:
            logger.warning("Failed to delete KFP %s from Elasticsearch: %s", kfp_id, e)
            return False

    async def get_cluster_health(self) -> Dict[str, Any]:
        """Get Elasticsearch cluster health status."""
        if not self.is_configured:
            return {"error": "Elasticsearch is not configured"}

        try:
            health = await self._request("GET", "/_cluster/health")
            return {
                "cluster_name": health.get("cluster_name"),
                "status": health.get("status"),  # green, yellow, red
                "number_of_nodes": health.get("number_of_nodes"),
                "number_of_data_nodes": health.get("number_of_data_nodes"),
                "active_primary_shards": health.get("active_primary_shards"),
                "active_shards": health.get("active_shards"),
                "relocating_shards": health.get("relocating_shards"),
                "initializing_shards": health.get("initializing_shards"),
                "unassigned_shards": health.get("unassigned_shards"),
                "pending_tasks": health.get("number_of_pending_tasks"),
            }
        except ElasticsearchError as e:
            return {"error": str(e)}

    async def get_index_stats(self, index_pattern: Optional[str] = None) -> Dict[str, Any]:
        """Get index statistics including document counts and sizes."""
        if not self.is_configured:
            return {"error": "Elasticsearch is not configured"}

        pattern = index_pattern or self.alert_index
        try:
            stats = await self._request("GET", f"/{pattern}/_stats")

            total = stats.get("_all", {}).get("total", {})
            primaries = stats.get("_all", {}).get("primaries", {})

            # Get indexing rate info
            indexing = primaries.get("indexing", {})

            return {
                "total_docs": primaries.get("docs", {}).get("count", 0),
                "total_size_bytes": primaries.get("store", {}).get("size_in_bytes", 0),
                "total_size_mb": round(primaries.get("store", {}).get("size_in_bytes", 0) / 1024 / 1024, 2),
                "index_total": indexing.get("index_total", 0),
                "index_time_ms": indexing.get("index_time_in_millis", 0),
                "index_current": indexing.get("index_current", 0),
                "search_total": primaries.get("search", {}).get("query_total", 0),
                "search_time_ms": primaries.get("search", {}).get("query_time_in_millis", 0),
                "indices_count": len(stats.get("indices", {})),
            }
        except ElasticsearchError as e:
            if "index_not_found" in str(e).lower():
                return {
                    "total_docs": 0,
                    "total_size_bytes": 0,
                    "total_size_mb": 0,
                    "index_total": 0,
                    "index_time_ms": 0,
                    "index_current": 0,
                    "search_total": 0,
                    "search_time_ms": 0,
                    "indices_count": 0,
                }
            return {"error": str(e)}

    async def get_ingest_stats(self) -> Dict[str, Any]:
        """Get ingest pipeline statistics."""
        if not self.is_configured:
            return {"error": "Elasticsearch is not configured"}

        try:
            stats = await self._request("GET", "/_nodes/stats/ingest")

            # Aggregate across all nodes
            total_count = 0
            total_failed = 0
            total_time_ms = 0
            pipelines = {}

            for node_id, node_data in stats.get("nodes", {}).items():
                ingest = node_data.get("ingest", {})
                total = ingest.get("total", {})
                total_count += total.get("count", 0)
                total_failed += total.get("failed", 0)
                total_time_ms += total.get("time_in_millis", 0)

                for pipeline_name, pipeline_stats in ingest.get("pipelines", {}).items():
                    if pipeline_name not in pipelines:
                        pipelines[pipeline_name] = {"count": 0, "failed": 0, "time_ms": 0}
                    pipelines[pipeline_name]["count"] += pipeline_stats.get("count", 0)
                    pipelines[pipeline_name]["failed"] += pipeline_stats.get("failed", 0)
                    pipelines[pipeline_name]["time_ms"] += pipeline_stats.get("time_in_millis", 0)

            return {
                "total_count": total_count,
                "total_failed": total_failed,
                "total_time_ms": total_time_ms,
                "pipelines": pipelines,
                "node_count": len(stats.get("nodes", {})),
            }
        except ElasticsearchError as e:
            return {"error": str(e)}

    async def discover_search(
        self,
        index_pattern: str,
        query: str = "*",
        time_field: str = "@timestamp",
        time_from: Optional[str] = "now-24h",
        time_to: Optional[str] = "now",
        size: int = 100,
        sort_field: Optional[str] = None,
        sort_order: str = "desc",
        fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Execute a discover-style search across Elasticsearch indices.

        Args:
            index_pattern: Index pattern to search (e.g., "logs-*", "filebeat-*")
            query: Query string in Lucene/KQL syntax (default "*" for all)
            time_field: Field to use for time filtering (default "@timestamp")
            time_from: Start time (ES date math, e.g., "now-24h", "2024-01-01")
            time_to: End time (ES date math, e.g., "now")
            size: Number of results to return (max 10000)
            sort_field: Field to sort by (defaults to time_field)
            sort_order: Sort order ("asc" or "desc")
            fields: Specific fields to return (None for all)

        Returns:
            Dict with hits, total count, and aggregations
        """
        if not self.is_configured:
            return {"error": "Elasticsearch is not configured", "hits": [], "total": 0}

        # Limit size to prevent memory issues
        size = min(size, 10000)

        # Build the query
        must_clauses = []

        # Add query string if not wildcard
        if query and query != "*":
            must_clauses.append({
                "query_string": {
                    "query": query,
                    "default_operator": "AND",
                    "analyze_wildcard": True,
                }
            })

        # Add time range filter if time_field exists
        if time_field and time_from:
            time_range = {"gte": time_from}
            if time_to:
                time_range["lte"] = time_to
            must_clauses.append({
                "range": {
                    time_field: time_range
                }
            })

        # Build search body
        search_body: Dict[str, Any] = {
            "size": size,
            "track_total_hits": True,
        }

        if must_clauses:
            search_body["query"] = {
                "bool": {
                    "must": must_clauses
                }
            }
        else:
            search_body["query"] = {"match_all": {}}

        # Add sorting
        sort_by = sort_field or time_field
        if sort_by:
            search_body["sort"] = [{sort_by: {"order": sort_order, "unmapped_type": "date"}}]

        # Add field filtering
        if fields:
            search_body["_source"] = fields

        try:
            # URL encode the index pattern
            encoded_index = index_pattern.replace(",", "%2C")
            result = await self._request(
                "POST",
                f"/{encoded_index}/_search",
                json=search_body
            )

            hits = result.get("hits", {})
            documents = []

            for hit in hits.get("hits", []):
                doc = {
                    "_index": hit.get("_index"),
                    "_id": hit.get("_id"),
                    **hit.get("_source", {})
                }
                documents.append(doc)

            return {
                "hits": documents,
                "total": hits.get("total", {}).get("value", 0),
                "max_score": hits.get("max_score"),
                "took_ms": result.get("took", 0),
                "timed_out": result.get("timed_out", False),
            }

        except ElasticsearchError as e:
            return {"error": str(e), "hits": [], "total": 0}

    async def discover_histogram(
        self,
        index_pattern: str,
        query: str = "*",
        time_field: str = "@timestamp",
        time_from: str = "now-24h",
        time_to: str = "now",
        interval: str = "1h",
    ) -> Dict[str, Any]:
        """Get a time histogram for discover visualization.

        Args:
            index_pattern: Index pattern to search
            query: Query string
            time_field: Time field for histogram
            time_from: Start time
            time_to: End time
            interval: Histogram interval (e.g., "1h", "1d", "5m")

        Returns:
            Dict with histogram buckets
        """
        if not self.is_configured:
            return {"error": "Elasticsearch is not configured", "buckets": []}

        # Build query
        must_clauses = []

        if query and query != "*":
            must_clauses.append({
                "query_string": {
                    "query": query,
                    "default_operator": "AND",
                    "analyze_wildcard": True,
                }
            })

        if time_field and time_from:
            must_clauses.append({
                "range": {
                    time_field: {"gte": time_from, "lte": time_to}
                }
            })

        search_body: Dict[str, Any] = {
            "size": 0,
            "aggs": {
                "events_over_time": {
                    "date_histogram": {
                        "field": time_field,
                        "fixed_interval": interval,
                        "min_doc_count": 0,
                        "extended_bounds": {
                            "min": time_from,
                            "max": time_to
                        }
                    }
                }
            }
        }

        if must_clauses:
            search_body["query"] = {"bool": {"must": must_clauses}}

        try:
            encoded_index = index_pattern.replace(",", "%2C")
            result = await self._request(
                "POST",
                f"/{encoded_index}/_search",
                json=search_body
            )

            buckets = result.get("aggregations", {}).get("events_over_time", {}).get("buckets", [])

            return {
                "buckets": [
                    {
                        "timestamp": b.get("key_as_string") or b.get("key"),
                        "count": b.get("doc_count", 0)
                    }
                    for b in buckets
                ],
                "total": sum(b.get("doc_count", 0) for b in buckets),
                "interval": interval,
            }

        except ElasticsearchError as e:
            return {"error": str(e), "buckets": []}

    async def list_indices(
        self,
        pattern: str = "*",
        include_system: bool = False,
        include_stats: bool = True,
    ) -> Dict[str, Any]:
        """List available Elasticsearch indices.

        Args:
            pattern: Index pattern to filter (e.g., "logs-*")
            include_system: Include system indices (starting with .)
            include_stats: Include document count and size stats

        Returns:
            Dict with list of indices and their metadata
        """
        if not self.is_configured:
            return {"error": "Elasticsearch is not configured", "indices": []}

        try:
            # Get index list with stats
            if include_stats:
                result = await self._request("GET", f"/_cat/indices/{pattern}?format=json&h=index,health,status,docs.count,store.size,creation.date")
            else:
                result = await self._request("GET", f"/_cat/indices/{pattern}?format=json&h=index,health,status")

            indices = []
            for idx in result:
                index_name = idx.get("index", "")

                # Filter system indices if requested
                if not include_system and index_name.startswith("."):
                    continue

                index_info = {
                    "name": index_name,
                    "health": idx.get("health"),
                    "status": idx.get("status"),
                }

                if include_stats:
                    index_info["doc_count"] = int(idx.get("docs.count", 0) or 0)
                    index_info["size"] = idx.get("store.size", "0b")
                    index_info["created"] = idx.get("creation.date")

                indices.append(index_info)

            # Sort by name
            indices.sort(key=lambda x: x["name"])

            return {
                "indices": indices,
                "total": len(indices),
            }

        except ElasticsearchError as e:
            return {"error": str(e), "indices": []}

    async def get_index_mappings(
        self,
        index_pattern: str,
    ) -> Dict[str, Any]:
        """Get field mappings for an index pattern.

        Args:
            index_pattern: Index or pattern to get mappings for

        Returns:
            Dict with field names, types, and metadata
        """
        if not self.is_configured:
            return {"error": "Elasticsearch is not configured", "fields": []}

        try:
            encoded_index = index_pattern.replace(",", "%2C")
            result = await self._request("GET", f"/{encoded_index}/_mapping")

            # Extract and flatten field mappings
            fields = []
            seen_fields = set()

            for index_name, index_data in result.items():
                mappings = index_data.get("mappings", {})
                properties = mappings.get("properties", {})

                def extract_fields(props: dict, prefix: str = ""):
                    for field_name, field_data in props.items():
                        full_name = f"{prefix}{field_name}" if prefix else field_name

                        if full_name in seen_fields:
                            continue
                        seen_fields.add(full_name)

                        field_type = field_data.get("type", "object")
                        field_info = {
                            "name": full_name,
                            "type": field_type,
                            "searchable": field_type not in ["object", "nested"],
                            "aggregatable": field_type in ["keyword", "long", "integer", "short", "byte", "double", "float", "date", "boolean", "ip"],
                        }

                        # Add format for date fields
                        if field_type == "date" and "format" in field_data:
                            field_info["format"] = field_data["format"]

                        fields.append(field_info)

                        # Recurse into nested properties
                        if "properties" in field_data:
                            extract_fields(field_data["properties"], f"{full_name}.")

                extract_fields(properties)

            # Sort fields by name
            fields.sort(key=lambda x: x["name"])

            return {
                "fields": fields,
                "total": len(fields),
                "index_pattern": index_pattern,
            }

        except ElasticsearchError as e:
            return {"error": str(e), "fields": []}

    async def get_field_stats(
        self,
        index_pattern: str,
        field: str,
        size: int = 10,
        time_field: Optional[str] = "@timestamp",
        time_from: Optional[str] = "now-24h",
        time_to: Optional[str] = "now",
    ) -> Dict[str, Any]:
        """Get statistics and top values for a specific field.

        Args:
            index_pattern: Index pattern to search
            field: Field to analyze
            size: Number of top values to return
            time_field: Time field for filtering
            time_from: Start time
            time_to: End time

        Returns:
            Dict with field statistics and top values
        """
        if not self.is_configured:
            return {"error": "Elasticsearch is not configured"}

        # Build time range filter
        query: Dict[str, Any] = {"match_all": {}}
        if time_field and time_from:
            query = {
                "bool": {
                    "filter": [{
                        "range": {
                            time_field: {"gte": time_from, "lte": time_to or "now"}
                        }
                    }]
                }
            }

        search_body = {
            "size": 0,
            "query": query,
            "aggs": {
                "field_stats": {
                    "terms": {
                        "field": field,
                        "size": size,
                        "missing": "__missing__"
                    }
                },
                "cardinality": {
                    "cardinality": {
                        "field": field
                    }
                },
                "value_count": {
                    "value_count": {
                        "field": field
                    }
                }
            }
        }

        try:
            encoded_index = index_pattern.replace(",", "%2C")
            result = await self._request(
                "POST",
                f"/{encoded_index}/_search",
                json=search_body
            )

            aggs = result.get("aggregations", {})
            buckets = aggs.get("field_stats", {}).get("buckets", [])

            top_values = []
            for b in buckets:
                key = b.get("key")
                if key == "__missing__":
                    key = None
                top_values.append({
                    "value": key,
                    "count": b.get("doc_count", 0)
                })

            return {
                "field": field,
                "index_pattern": index_pattern,
                "top_values": top_values,
                "unique_count": aggs.get("cardinality", {}).get("value", 0),
                "total_count": aggs.get("value_count", {}).get("value", 0),
                "doc_count": result.get("hits", {}).get("total", {}).get("value", 0),
            }

        except ElasticsearchError as e:
            return {"error": str(e)}

    async def ioc_hunt(
        self,
        ioc_value: str,
        ioc_type: Optional[str] = None,
        index_pattern: str = "*,-.*",
        time_field: str = "@timestamp",
        time_from: Optional[str] = "now-30d",
        time_to: Optional[str] = "now",
        size: int = 100,
    ) -> Dict[str, Any]:
        """Hunt for an IOC (Indicator of Compromise) across all indices.

        Automatically detects IOC type and searches relevant fields.

        Args:
            ioc_value: The IOC value to search for (IP, hash, domain, URL, email)
            ioc_type: Override auto-detection (ip, hash, domain, url, email)
            index_pattern: Indices to search (default excludes system indices)
            time_field: Time field for filtering
            time_from: Start time
            time_to: End time
            size: Max results per index

        Returns:
            Dict with hits grouped by index and IOC metadata
        """
        if not self.is_configured:
            return {"error": "Elasticsearch is not configured", "hits": [], "total": 0}

        import re

        # Auto-detect IOC type if not provided
        if not ioc_type:
            ioc_type = self._detect_ioc_type(ioc_value)

        # Define fields to search based on IOC type
        field_patterns = {
            "ip": [
                "source.ip", "destination.ip", "client.ip", "server.ip",
                "host.ip", "source_ip", "dest_ip", "src_ip", "dst_ip",
                "ip", "ipaddress", "remote_ip", "local_ip", "*ip*"
            ],
            "hash": [
                "file.hash.*", "hash.*", "file.sha256", "file.sha1", "file.md5",
                "sha256", "sha1", "md5", "hash", "file_hash", "process.hash.*"
            ],
            "domain": [
                "dns.question.name", "url.domain", "destination.domain",
                "host.name", "domain", "hostname", "server.domain",
                "destination.registered_domain", "url.registered_domain"
            ],
            "url": [
                "url.full", "url.original", "http.request.url", "url",
                "request.url", "uri", "http_url"
            ],
            "email": [
                "user.email", "email.from", "email.to", "source.user.email",
                "destination.user.email", "email", "sender", "recipient"
            ],
        }

        search_fields = field_patterns.get(ioc_type, ["*"])

        # Build multi-field query
        should_clauses = []

        # For IPs, use term queries on IP fields
        if ioc_type == "ip":
            for field in search_fields:
                if "*" in field:
                    should_clauses.append({
                        "query_string": {
                            "query": f"{ioc_value}",
                            "fields": [field],
                            "default_operator": "AND"
                        }
                    })
                else:
                    should_clauses.append({"term": {field: ioc_value}})
        else:
            # For other types, use multi_match and query_string
            should_clauses.append({
                "multi_match": {
                    "query": ioc_value,
                    "fields": [f for f in search_fields if "*" not in f],
                    "type": "phrase"
                }
            })
            # Also search with wildcards for flexible matching
            should_clauses.append({
                "query_string": {
                    "query": f"\"{ioc_value}\"",
                    "default_operator": "AND",
                    "analyze_wildcard": True
                }
            })

        # Build time filter
        must_clauses = []
        if time_field and time_from:
            must_clauses.append({
                "range": {
                    time_field: {"gte": time_from, "lte": time_to or "now"}
                }
            })

        search_body: Dict[str, Any] = {
            "size": size,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "must": must_clauses if must_clauses else [{"match_all": {}}],
                    "should": should_clauses,
                    "minimum_should_match": 1
                }
            },
            "sort": [{time_field: {"order": "desc", "unmapped_type": "date"}}] if time_field else [],
            "aggs": {
                "by_index": {
                    "terms": {
                        "field": "_index",
                        "size": 50
                    }
                }
            }
        }

        try:
            encoded_index = index_pattern.replace(",", "%2C")
            result = await self._request(
                "POST",
                f"/{encoded_index}/_search",
                json=search_body
            )

            hits = result.get("hits", {})
            documents = []

            for hit in hits.get("hits", []):
                doc = {
                    "_index": hit.get("_index"),
                    "_id": hit.get("_id"),
                    "_score": hit.get("_score"),
                    **hit.get("_source", {})
                }
                documents.append(doc)

            # Group hits by index
            index_buckets = result.get("aggregations", {}).get("by_index", {}).get("buckets", [])
            indices_found = [
                {"index": b["key"], "count": b["doc_count"]}
                for b in index_buckets
            ]

            return {
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "hits": documents,
                "total": hits.get("total", {}).get("value", 0),
                "indices_found": indices_found,
                "took_ms": result.get("took", 0),
                "search_fields": search_fields,
            }

        except ElasticsearchError as e:
            return {"error": str(e), "hits": [], "total": 0}

    def _detect_ioc_type(self, value: str) -> str:
        """Auto-detect the type of IOC based on its format."""
        import re

        value = value.strip()

        # IPv4
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value):
            return "ip"

        # IPv6 (simplified check)
        if re.match(r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$', value):
            return "ip"

        # MD5 hash (32 hex chars)
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return "hash"

        # SHA1 hash (40 hex chars)
        if re.match(r'^[a-fA-F0-9]{40}$', value):
            return "hash"

        # SHA256 hash (64 hex chars)
        if re.match(r'^[a-fA-F0-9]{64}$', value):
            return "hash"

        # URL
        if re.match(r'^https?://', value, re.IGNORECASE):
            return "url"

        # Email
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', value):
            return "email"

        # Domain (basic check - contains dot, no spaces, not IP)
        if '.' in value and ' ' not in value and not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value):
            return "domain"

        # Default to generic search
        return "unknown"

    async def ioc_hunt_bulk(
        self,
        ioc_values: List[str],
        index_pattern: str = "*,-.*",
        time_from: Optional[str] = "now-30d",
        time_to: Optional[str] = "now",
    ) -> Dict[str, Any]:
        """Hunt for multiple IOCs at once.

        Args:
            ioc_values: List of IOC values to search for
            index_pattern: Indices to search
            time_from: Start time
            time_to: End time

        Returns:
            Dict with results for each IOC
        """
        if not self.is_configured:
            return {"error": "Elasticsearch is not configured", "results": []}

        results = []
        found_count = 0
        not_found_count = 0

        for ioc in ioc_values[:100]:  # Limit to 100 IOCs
            result = await self.ioc_hunt(
                ioc_value=ioc.strip(),
                index_pattern=index_pattern,
                time_from=time_from,
                time_to=time_to,
                size=10  # Limit per IOC for bulk search
            )

            ioc_result = {
                "ioc_value": ioc,
                "ioc_type": result.get("ioc_type", "unknown"),
                "found": result.get("total", 0) > 0,
                "hit_count": result.get("total", 0),
                "indices": [i["index"] for i in result.get("indices_found", [])],
            }
            results.append(ioc_result)

            if ioc_result["found"]:
                found_count += 1
            else:
                not_found_count += 1

        return {
            "results": results,
            "total_searched": len(results),
            "found_count": found_count,
            "not_found_count": not_found_count,
        }
