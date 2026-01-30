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
        # Primary path: threat.technique.id/name, threat.tactic.name (ECS/seed data format)
        threat = source.get("threat", {})
        mitre_technique_id = None
        mitre_technique_name = None
        mitre_tactic_name = None

        if isinstance(threat, dict):
            technique = threat.get("technique", {})
            tactic = threat.get("tactic", {})
            if isinstance(technique, dict):
                mitre_technique_id = technique.get("id")
                mitre_technique_name = technique.get("name")
            elif isinstance(technique, list) and technique:
                mitre_technique_id = technique[0].get("id")
                mitre_technique_name = technique[0].get("name")
            if isinstance(tactic, dict):
                mitre_tactic_name = tactic.get("name")
            elif isinstance(tactic, list) and tactic:
                mitre_tactic_name = tactic[0].get("name")

        # Fallback: signal.rule.threat[0].technique[0] (Elastic SIEM format)
        if not mitre_technique_id:
            signal_threats = source.get("signal", {}).get("rule", {}).get("threat", [])
            if isinstance(signal_threats, list) and signal_threats:
                first_threat = signal_threats[0]
                if isinstance(first_threat, dict):
                    techniques = first_threat.get("technique", [])
                    if isinstance(techniques, list) and techniques:
                        mitre_technique_id = techniques[0].get("id")
                        mitre_technique_name = techniques[0].get("name")
                    tactic_obj = first_threat.get("tactic", {})
                    if isinstance(tactic_obj, dict):
                        mitre_tactic_name = tactic_obj.get("name")

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
