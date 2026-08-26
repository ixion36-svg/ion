"""Elasticsearch integration service for ION.

Provides functionality to fetch alerts and security events from Elasticsearch.
"""

import asyncio
import hashlib
import logging
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

import httpx

from ion.core.circuit_breaker import es_breaker
from ion.core.config import get_elasticsearch_config, get_ssl_verify
from ion.core.safe_errors import safe_error

logger = logging.getLogger(__name__)

# Shared persistent httpx client — avoids per-request connection overhead.
# Bound to the event loop it was created on: an httpx.AsyncClient cannot be
# reused across loops. Background services run ES queries via asyncio.run()
# (a fresh, short-lived loop each cycle), so a single global client shared with
# the persistent request loop raised "RuntimeError: Event loop is closed" when
# one loop tried to use/close connections owned by another. We therefore track
# the binding loop and recreate the client whenever the running loop differs.
_es_client: Optional[httpx.AsyncClient] = None
_es_client_creds: Optional[str] = None  # fingerprint of (headers, auth) used at creation
_es_client_loop: Optional[asyncio.AbstractEventLoop] = None  # loop the client is bound to
# guards every read-check-create-assign of the slot above. Without it
# a background thread's asyncio.run() cycle could rebind the global between a
# web-loop caller's creation and its `return`, handing that caller a client
# bound to a throwaway loop — the exact "Event loop is closed" crash the
# loop-binding fix was meant to close.
_es_client_lock = threading.Lock()


def _creds_fingerprint(headers: Dict, auth: Optional[tuple]) -> str:
    raw = repr(sorted(headers.items())) + repr(auth)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _dispose_client(
    client: Optional[httpx.AsyncClient],
    bound_loop: Optional[asyncio.AbstractEventLoop],
    current_loop: Optional[asyncio.AbstractEventLoop],
) -> None:
    """Best-effort aclose of a displaced client. Never raises.

    asyncio.run() teardown does NOT close httpx connection pools, so simply
    dropping the reference leaks keepalive sockets. Closing cross-loop is
    safe via run_coroutine_threadsafe as long as the owning loop still runs;
    only when it is already dead do we fall back to dropping the reference
    (GC finalizers reclaim the sockets).
    """
    if client is None or client.is_closed:
        return
    try:
        if current_loop is not None and current_loop is bound_loop:
            current_loop.create_task(client.aclose())
        elif bound_loop is not None and not bound_loop.is_closed():
            asyncio.run_coroutine_threadsafe(client.aclose(), bound_loop)
        elif bound_loop is None and current_loop is None:
            asyncio.run(client.aclose())
        # else: owning loop already dead — nothing can run its aclose; drop.
    except Exception:  # noqa: BLE001 — disposal must never break a request
        pass


def _get_es_client(headers, auth, verify_ssl, timeout) -> httpx.AsyncClient:
    """Return (and lazily create) the shared async client for the current loop.

    Recreates the client when (a) credentials change — so a runtime credential
    update (e.g. admin wizard) is picked up without a restart — OR (b) the
    running event loop differs from the one the client was bound to. The loop
    check is what prevents "Event loop is closed": background services issue ES
    queries via asyncio.run() on throwaway loops; reusing a client bound to a
    now-dead loop would fail.

    Thread-safe: the whole check-create-assign runs under _es_client_lock and
    callers receive a local reference, never a re-read of the mutable global.
    """
    global _es_client, _es_client_creds, _es_client_loop
    fp = _creds_fingerprint(headers, auth)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None  # sync context (e.g. unit tests) — single shared slot
    with _es_client_lock:
        client = _es_client
        if (
            client is None
            or client.is_closed
            or fp != _es_client_creds
            or loop is not _es_client_loop
        ):
            _dispose_client(client, _es_client_loop, loop)
            client = httpx.AsyncClient(
                headers=headers,
                auth=auth,
                verify=verify_ssl,
                timeout=timeout,
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            )
            # test/debug bookkeeping: which loop this client belongs to
            client._ion_bound_loop = loop  # type: ignore[attr-defined]
            _es_client = client
            _es_client_creds = fp
            _es_client_loop = loop
        return client


def _close_es_client() -> None:
    """Close the shared ES client (call on config change)."""
    global _es_client, _es_client_creds, _es_client_loop
    try:
        current = asyncio.get_running_loop()
    except RuntimeError:
        current = None
    with _es_client_lock:
        _dispose_client(_es_client, _es_client_loop, current)
        _es_client = None
        _es_client_creds = None
        _es_client_loop = None


def _redact_url(url: str) -> str:
    """Strip embedded user:password credentials from a URL so it is safe to log."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
        if parts.username or parts.password:
            host = parts.hostname or ""
            netloc = f"{host}:{parts.port}" if parts.port else host
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        pass
    return url


def _proc_field(source: dict, *keys: str) -> Any:
    """Read a process field from an ES alert ``_source``, flat-dotted or nested."""
    for key in keys:
        if key in source and source[key] not in (None, ""):
            return source[key]
    for key in keys:
        cur: Any = source
        for part in key.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                cur = None
                break
        if cur not in (None, ""):
            return cur
    return None


def _first(v: Any) -> Any:
    """ES fields are often single-element arrays — collapse to a scalar."""
    if isinstance(v, list):
        return v[0] if v else None
    return v


def _proc_node(src: dict, prefix: str, role: str, is_alert: bool = False) -> Optional[Dict[str, Any]]:
    """Build one process node from ``src`` at ``{prefix}.*`` (e.g. ``process`` or
    ``process.parent``). Returns None when no process signal is present."""
    name = _first(_proc_field(src, f"{prefix}.name"))
    executable = _first(_proc_field(src, f"{prefix}.executable"))
    pid = _first(_proc_field(src, f"{prefix}.pid"))
    entity_id = _first(_proc_field(src, f"{prefix}.entity_id"))
    parent_entity_id = _first(_proc_field(src, f"{prefix}.parent.entity_id"))
    command_line = _first(_proc_field(src, f"{prefix}.command_line"))
    # Alert process: fall back to the doc's top-level user as the owning user.
    user = _first(_proc_field(src, f"{prefix}.user.name")) or (
        _first(_proc_field(src, "user.name")) if is_alert else None
    )
    if not any([name, executable, pid, entity_id, command_line]):
        return None
    if not name and executable:
        name = str(executable).replace("\\", "/").rsplit("/", 1)[-1]
    return {
        "role": role,
        "is_alert": is_alert,
        "name": name,
        "executable": executable,
        "pid": pid,
        "entity_id": entity_id,
        "parent_entity_id": parent_entity_id,
        "command_line": command_line,
        "user": user,
    }


def build_process_tree(source: Optional[dict]) -> Dict[str, Any]:
    """Build an *alert-local* process hierarchy from a single ES alert ``_source``.

    The fallback path when no process-events index is configured: the chain is
    bounded by what the alert document itself carries — the alert's own
    ``process.*``, ``process.parent.*`` (and ``process.parent.parent.*`` when
    present). ``process.Ext.ancestry`` (Elastic Defend's entity-id list) records
    the TRUE ancestry depth even when intermediate processes aren't named in the
    alert — surfaced as ``truncated_ancestors`` so the UI can say "+N earlier
    ancestors (not in alert data)" rather than implying the chain is complete.
    """
    src = source or {}
    ordered = [
        n
        for n in (
            _proc_node(src, "process.parent.parent", "grandparent"),
            _proc_node(src, "process.parent", "parent"),
            _proc_node(src, "process", "alert", is_alert=True),
        )
        if n
    ]
    if not ordered:
        return {
            "available": False, "nodes": [], "children": [],
            "ancestry_depth": 0, "truncated_ancestors": 0, "mode": "alert-local",
        }
    for level, n in enumerate(ordered):
        n["level"] = level
    ancestry = _proc_field(src, "process.Ext.ancestry")
    ancestry_depth = len(ancestry) if isinstance(ancestry, list) else 0
    named_ancestors = sum(1 for n in ordered if not n["is_alert"])
    return {
        "available": True,
        "nodes": ordered,
        "children": [],
        "ancestry_depth": ancestry_depth,
        "truncated_ancestors": max(0, ancestry_depth - named_ancestors),
        "mode": "alert-local",
    }


def assemble_full_process_tree(
    alert_source: Optional[dict], event_docs: Optional[List[dict]]
) -> Dict[str, Any]:
    """Build the *full* process explorer from resolved process-event docs.

    The Kibana-analyzer-style path, used when a process-events index is wired
    (``ION_ELASTICSEARCH_PROCESS_EVENTS_INDEX``). ``event_docs`` are the ``_source`` dicts of
    process events resolved by entity-id; this walks the alert's
    ``process.Ext.ancestry`` (parent-first) into a NAMED root→leaf chain, flags
    the alert's own process, and attaches the alert process's direct children
    (events whose ``process.parent.entity_id`` == the alert process entity-id).
    Falls back to the alert-local view when there's nothing to resolve.
    """
    src = alert_source or {}
    alert_entity = _first(_proc_field(src, "process.entity_id"))
    ancestry = _proc_field(src, "process.Ext.ancestry")
    ancestry = [a for a in ancestry if a] if isinstance(ancestry, list) else []

    # Index resolved events by entity-id; collect direct children of the alert.
    by_entity: Dict[str, Dict[str, Any]] = {}
    children: List[Dict[str, Any]] = []
    for ev in event_docs or []:
        n = _proc_node(ev, "process", "ancestor")
        if not n:
            continue
        if n["entity_id"]:
            by_entity[n["entity_id"]] = n
        if (
            alert_entity
            and n.get("parent_entity_id") == alert_entity
            and n["entity_id"] != alert_entity
        ):
            child = dict(n)
            child["role"] = "child"
            children.append(child)

    alert_node = _proc_node(src, "process", "alert", is_alert=True)

    ancestors: List[Dict[str, Any]] = []
    unresolved = 0
    for aid in ancestry:  # parent-first in ECS
        resolved = by_entity.get(aid)
        if resolved:
            node = dict(resolved)
            node["role"] = "ancestor"
            ancestors.append(node)
        else:
            unresolved += 1
    ancestors.reverse()  # → root … parent

    # No ancestry list (non-Defend alert): use the alert doc's own parent chain.
    if not ancestors and not ancestry:
        for pfx, role in (("process.parent.parent", "grandparent"), ("process.parent", "parent")):
            pn = _proc_node(src, pfx, role)
            if pn:
                ancestors.append(pn)

    chain = [n for n in ancestors if n]
    if alert_node:
        chain.append(alert_node)
    if not chain:
        return {
            "available": False, "nodes": [], "children": [],
            "ancestry_depth": len(ancestry), "truncated_ancestors": 0, "mode": "events-index",
        }
    for level, n in enumerate(chain):
        n["level"] = level

    # De-dup children by entity-id; seat them one level below the alert process.
    alert_level = chain[-1]["level"]
    seen: set = set()
    kids: List[Dict[str, Any]] = []
    for c in children:
        eid = c.get("entity_id")
        if eid and eid in seen:
            continue
        if eid:
            seen.add(eid)
        c["level"] = alert_level + 1
        kids.append(c)

    return {
        "available": True,
        "nodes": chain,
        "children": kids,
        "ancestry_depth": len(ancestry),
        "truncated_ancestors": unresolved,
        "mode": "events-index",
    }


@dataclass
class ElasticsearchAlert:
    """Represents an alert from Elasticsearch."""

    id: str
    title: str
    severity: str  # critical, high, medium, low, info
    status: str  # open, acknowledged, closed
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
    geo_data: Dict[str, Any] = None
    source_system: Optional[str] = None
    # Arkime PCAP linkage — alerts from a network pipeline carry
    # `network.community_id` (flow hash, shared with Arkime) and `node`
    # (Arkime capture node name).
    network_community_id: Optional[str] = None
    arkime_node: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    # Process & file context — critical for triage
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    parent_process_name: Optional[str] = None
    file_name: Optional[str] = None
    file_hash: Optional[str] = None
    file_path: Optional[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.raw_data is None:
            self.raw_data = {}
        if self.geo_data is None:
            self.geo_data = {}

    def to_dict(self, include_raw: bool = True) -> Dict[str, Any]:
        """Convert to dictionary for API response.

        Args:
            include_raw: Include the full raw_data field. Set False for list
                views to cut ~65% of payload size.
        """
        d = {
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
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "mitre_tactic_name": self.mitre_tactic_name,
            "geo_data": self.geo_data,
            "source_system": self.source_system,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "parent_process_name": self.parent_process_name,
            "file_name": self.file_name,
            "file_hash": self.file_hash,
            "file_path": self.file_path,
            "network_community_id": self.network_community_id,
            "arkime_node": self.arkime_node,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
        }
        if include_raw:
            d["raw_data"] = self.raw_data
        return d


class ElasticsearchError(Exception):
    """Exception raised for Elasticsearch errors."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


# Module-level cache for assignment users (survives across request instances)
_assignment_users_cache: List[Dict[str, str]] = []
_assignment_users_cached_at: Optional[datetime] = None
_ASSIGNMENT_CACHE_TTL = timedelta(minutes=5)


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
        verify_ssl: Optional[bool] = None,
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
        raw_url = (url or config.get("url", "")).rstrip("/")
        # Strip any embedded user:pass from the URL so credentials never end up
        # in logs, error messages, or stack traces. The dedicated username/password
        # fields below remain the only source of auth.
        self.url = _redact_url(raw_url)
        self.api_key = api_key or config.get("api_key", "")
        self.username = username or config.get("username", "")
        self.password = password or config.get("password", "")
        # If credentials were embedded in the URL and no explicit username/password
        # was provided, promote them to the auth fields so behaviour is preserved.
        if raw_url != self.url:
            try:
                _embedded = urlsplit(raw_url)
                if not self.username and _embedded.username:
                    self.username = _embedded.username
                if not self.password and _embedded.password:
                    self.password = _embedded.password
            except Exception:
                pass
        self.alert_index = alert_index or config.get("alert_index", ".alerts-security.alerts-*,alerts-*")
        self.case_index = case_index or config.get("case_index", "ion-cases")
        self.kfp_index = config.get("kfp_index", "ion-kfp")
        # Optional raw process-events index for the full process explorer
        # (Kibana-analyzer-style ancestry/children resolution). Empty = off, in
        # which case the explorer degrades to the alert-local tree. Set via
        # ION_ELASTICSEARCH_PROCESS_EVENTS_INDEX / config.json / admin wizard.
        self.process_events_index = config.get("process_events_index", "")
        self.verify_ssl = verify_ssl if verify_ssl is not None else config.get("verify_ssl", True)
        # User mapping for alert assignment
        self.user_index = config.get("user_index", "")
        self.user_field = config.get("user_field", "")
        self.assignment_field = config.get("assignment_field", "kibana.alert.workflow_user")

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
        *,
        timeout: Optional[float] = None,
        **kwargs,
    ) -> Any:
        """Make an authenticated request to Elasticsearch.

        v0.15.1: ``timeout`` (seconds) overrides the client default for a
        single request. Heavy aggregations (e.g. the daily-standup
        log-source-health checks) pass a longer timeout so they do not
        race the global default. Without this override, the WEF check on
        a busy estate could exceed 10 s and time out.

        Global default is configurable via ``ION_ES_TIMEOUT`` (seconds);
        defaults to 30 s.
        """
        if not self.is_configured:
            raise ElasticsearchError("Elasticsearch integration is not configured")

        url = f"{self.url}/{endpoint.lstrip('/')}"

        # For search requests on multi-index patterns, skip missing indices
        # expand_wildcards=open,hidden ensures .alerts-* (system/hidden) indices are matched
        if "/_search" in endpoint:
            sep = "&" if "?" in url else "?"
            url += f"{sep}ignore_unavailable=true&allow_no_indices=true&expand_wildcards=open,hidden"

        try:
            try:
                _default_timeout = float(os.environ.get("ION_ES_TIMEOUT", "30"))
            except Exception:
                _default_timeout = 30.0
            client = _get_es_client(
                self._get_headers(),
                self._get_auth(),
                get_ssl_verify(self.verify_ssl),
                httpx.Timeout(_default_timeout, connect=3.0),
            )
            # Per-request timeout override — used by heavy aggregations.
            if timeout is not None:
                kwargs["timeout"] = httpx.Timeout(float(timeout), connect=3.0)
            response = await client.request(method, url, **kwargs)
            # ES responded — any HTTP status means connectivity is healthy.
            es_breaker.record_success()
        except httpx.ConnectError as e:
            es_breaker.record_failure()
            raise ElasticsearchError(f"Failed to connect to Elasticsearch: {e}")
        except httpx.ReadError as e:
            es_breaker.record_failure()
            raise ElasticsearchError(f"Connection error reading from Elasticsearch: {e}")
        except httpx.TimeoutException as e:
            es_breaker.record_failure()
            raise ElasticsearchError(f"Request to Elasticsearch timed out: {e}")
        except httpx.HTTPError as e:
            es_breaker.record_failure()
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

    async def suggest_user_profiles(
        self, name: str, size: int = 5
    ) -> List[Dict[str, Any]]:
        """Suggest Elasticsearch user profiles by username/email/full-name match.

        Hits the ES native API `POST /_security/profile/_suggest`. This is the
        correct endpoint for username → UID resolution; the equivalent Kibana
        endpoint `POST /internal/security/user_profile/_suggest` is 404 in
        Kibana 8.11+ unless invoked from a logged-in browser session.

        Returns:
            list of profile dicts shaped like
            `{"uid": "...", "user": {"username": ..., "email": ..., ...}}`
        """
        if not self.is_configured:
            return []
        try:
            result = await self._request(
                "POST",
                "/_security/profile/_suggest",
                json={"name": name, "size": size},
            )
            return result.get("profiles", []) if isinstance(result, dict) else []
        except ElasticsearchError as e:
            logger.debug("ES profile suggest failed for %r: %s", name, e)
            return []

    async def resolve_user_uid(self, username: str) -> Optional[str]:
        """Resolve an exact username to its Elasticsearch user profile UID.

        Calls `suggest_user_profiles` and returns only an EXACT username match
        — fuzzy hits are dropped to avoid attributing alerts to the wrong user.
        Returns None if the username has no profile (user has never logged
        into Kibana, or doesn't exist in ES).
        """
        profiles = await self.suggest_user_profiles(username, size=10)
        for p in profiles:
            user = p.get("user", {}) if isinstance(p, dict) else {}
            if isinstance(user, dict) and user.get("username") == username:
                return p.get("uid")
        return None

    async def bulk_get_user_profiles(
        self, uids: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """Resolve a list of UIDs back to their user profiles in one call.

        Used when reading Kibana case `assignees: [{uid: ...}]` — Kibana
        stores assignees by opaque UID, this maps them back to usernames.
        Returns a `{uid: profile}` map; missing UIDs are simply absent.
        """
        if not self.is_configured or not uids:
            return {}
        try:
            result = await self._request(
                "GET",
                f"/_security/profile/{','.join(uids)}",
            )
        except ElasticsearchError as e:
            logger.debug("ES profile bulk_get failed for %d uids: %s", len(uids), e)
            return {}
        out: Dict[str, Dict[str, Any]] = {}
        for p in (result.get("profiles", []) if isinstance(result, dict) else []):
            uid = p.get("uid") if isinstance(p, dict) else None
            if uid:
                out[uid] = p
        return out

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
            # GET / requires cluster monitor privilege; fall back to a
            # lightweight index query that only needs read access.
            if "403" in str(e) or "unauthorized" in str(e).lower() or "security_exception" in str(e).lower():
                try:
                    result = await self._request(
                        "POST",
                        f"/{self.alert_index}/_search",
                        json={"size": 0},
                    )
                    return {
                        "connected": True,
                        "cluster_name": None,
                        "version": None,
                        "note": "Limited permissions — cluster info unavailable",
                    }
                except ElasticsearchError:
                    pass
            return {
                "connected": False,
                "error": safe_error(e, "elasticsearch.test_connection"),
            }

    async def get_alerts(
        self,
        hours: int = 24,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        include_closed: bool = False,
        time_from: Optional[str] = None,
        time_to: Optional[str] = None,
        system: Optional[str] = None,
    ) -> List[ElasticsearchAlert]:
        """Fetch alerts from Elasticsearch.

        Args:
            hours: Number of hours to look back (ignored if time_from is set)
            severity: Filter by severity (critical, high, medium, low, info)
            status: Filter by status (open, acknowledged, closed)
            limit: Maximum number of alerts to return
            include_closed: Include closed/resolved alerts (default False).
                When False, alerts with workflow_status=closed are excluded
                to avoid exposing data from completed investigations.
            time_from: Absolute start time (ISO 8601). Overrides hours param.
            time_to: Absolute end time (ISO 8601). Defaults to now.
        """
        # Build query — use absolute range if provided, otherwise relative hours
        if time_from:
            time_range = {"gte": time_from}
            if time_to:
                time_range["lte"] = time_to
            else:
                time_range["lte"] = "now"
        else:
            time_range = {"gte": f"now-{hours}h", "lte": "now"}

        must_clauses = [
            {"range": {"@timestamp": time_range}}
        ]

        if severity:
            # was case-sensitive `term` queries on a single
            # casing — Kibana indices store severity lowercase but
            # other producers (Wazuh, custom rules) ship "Critical" or
            # "CRITICAL". The single-casing match silently dropped
            # those, leaving the daily SOC standup looking empty even
            # when criticals existed. Fan out to all common casings via
            # `terms`. Cheap on ES — same inverted-index lookup.
            sev_str = str(severity)
            sev_variants = list({sev_str.lower(), sev_str.capitalize(), sev_str.upper(), sev_str})
            must_clauses.append({
                "bool": {
                    "should": [
                        {"terms": {"event.severity": sev_variants}},
                        {"terms": {"kibana.alert.severity": sev_variants}},
                        {"terms": {"signal.rule.severity": sev_variants}},
                        {"terms": {"severity": sev_variants}},
                    ],
                    "minimum_should_match": 1
                }
            })

        if status:
            must_clauses.append({
                "bool": {
                    "should": [
                        {"term": {"kibana.alert.workflow_status": status}},
                        {"term": {"kibana.alert.status": status}},
                        {"term": {"status": status}},
                        {"term": {"state": status}},
                    ],
                    "minimum_should_match": 1
                }
            })

        if system:
            # Filter by data_stream.namespace which is what we surface as
            # the alert's `source_system` field. Lowercased to match the
            # ES storage convention enforced by CyAB on save.
            must_clauses.append({
                "term": {"data_stream.namespace": system.strip().lower()}
            })

        must_not_clauses = [
            {"exists": {"field": "kibana.alert.building_block_type"}}
        ]

        # Exclude closed alerts by default to avoid exposing completed investigations
        if not include_closed and not status:
            must_not_clauses.extend([
                {"term": {"kibana.alert.workflow_status": "closed"}},
                {"term": {"status": "closed"}},
                {"term": {"status": "resolved"}},
            ])

        query = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": must_clauses,
                    "must_not": must_not_clauses,
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

    async def get_alerts_histogram(
        self,
        hours: int = 24,
        interval: str = "1h",
        include_closed: bool = False,
    ) -> List[Dict[str, Any]]:
        """Return a time-bucketed count of alerts for the dashboard sparkline.

        Uses a date_histogram aggregation with extended_bounds so empty
        buckets are zero-filled — the sparkline then plots a continuous
        N-point line even on quiet windows.

        Args:
            hours: Lookback window (default 24h).
            interval: ES fixed_interval (default "1h" → 24 points).
            include_closed: Count closed alerts too (default False — the
                default dashboard view shows only active work).

        Returns: [{"ts": iso_string, "count": int}, ...] oldest → newest.
        Empty list on any failure.
        """
        must_clauses = [
            {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}}
        ]
        must_not_clauses = [
            {"exists": {"field": "kibana.alert.building_block_type"}}
        ]
        if not include_closed:
            must_not_clauses.extend([
                {"term": {"kibana.alert.workflow_status": "closed"}},
                {"term": {"status": "closed"}},
                {"term": {"status": "resolved"}},
            ])

        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": must_clauses,
                    "must_not": must_not_clauses,
                }
            },
            "aggs": {
                "over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": interval,
                        "min_doc_count": 0,
                        "extended_bounds": {
                            "min": f"now-{hours}h",
                            "max": "now",
                        },
                    }
                }
            },
        }

        try:
            result = await self._request(
                "POST",
                f"/{self.alert_index}/_search",
                json=query,
            )
        except ElasticsearchError as e:
            if "index_not_found" in str(e).lower() or "404" in str(e):
                return []
            logger.warning("alert histogram failed: %s", e)
            return []
        except Exception as e:
            logger.warning("alert histogram unexpected: %s", type(e).__name__)
            return []

        buckets = (
            result.get("aggregations", {})
            .get("over_time", {})
            .get("buckets", [])
        )
        return [
            {
                "ts": b.get("key_as_string") or b.get("key"),
                "count": int(b.get("doc_count", 0)),
            }
            for b in buckets
        ]

    @staticmethod
    def _get_field(source: Dict[str, Any], dotted_path: str, default=None):
        """Get a field value from ES _source using dotted path.

        Handles both flat dotted keys (ES 8.x: {"kibana.alert.rule.name": "..."})
        and nested objects (ES 9.x: {"kibana": {"alert": {"rule": {"name": "..."}}}}).
        """
        # First try flat dotted key (most common in ES 8.x alert indices)
        val = source.get(dotted_path)
        if val is not None:
            return val

        # Then try nested object traversal (ES 9.x may use this format)
        parts = dotted_path.split(".")
        current = source
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
                if current is None:
                    return default
            else:
                return default
        return current if current is not None else default

    def _parse_alert(self, alert_id: str, source: Dict[str, Any]) -> Optional[ElasticsearchAlert]:
        """Parse an alert from various Elasticsearch formats."""
        # Try to extract common fields from different alert formats
        # Supports: Elastic Security (SIEM), Watcher, and custom formats
        _f = self._get_field  # shorthand

        # Timestamp
        timestamp_str = (
            source.get("@timestamp") or
            source.get("timestamp") or
            _f(source, "kibana.alert.start") or
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
            _f(source, "kibana.alert.rule.name") or
            _f(source, "signal.rule.name") or
            _f(source, "rule.name") or
            source.get("alert_type") or
            _f(source, "event.action") or
            source.get("message", "")[:100] or
            "Unknown Alert"
        )

        # Severity
        severity = (
            _f(source, "kibana.alert.severity") or
            _f(source, "event.severity") or
            _f(source, "signal.rule.severity") or
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

        # Status — prefer workflow_status (what ION syncs) over alert status
        status = (
            _f(source, "kibana.alert.workflow_status") or
            _f(source, "kibana.alert.status") or
            source.get("status") or
            source.get("state") or
            "open"
        )
        status_map = {
            "active": "open", "open": "open", "new": "open", "triggered": "open",
            "acknowledged": "acknowledged", "acked": "acknowledged", "in_progress": "acknowledged",
            "resolved": "closed", "closed": "closed", "ok": "closed",
        }
        status = status_map.get(str(status).lower(), "open")

        # Source type
        alert_source = "custom"
        if _f(source, "kibana.alert.rule.name") or "kibana.alert" in str(source):
            alert_source = "siem"
        elif "watcher" in str(source) or source.get("watch_id"):
            alert_source = "watcher"
        elif source.get("signal") or _f(source, "signal.rule.name"):
            alert_source = "siem"

        # Message
        message = (
            source.get("message") or
            _f(source, "kibana.alert.reason") or
            _f(source, "signal.rule.description") or
            _f(source, "rule.description") or
            title
        )

        # Host — prefer FQDN (host.hostname), fall back to short name
        host = (
            _f(source, "host.hostname") or
            _f(source, "host.name") or
            _f(source, "agent.hostname") or
            _f(source, "agent.name") or
            _f(source, "observer.hostname") or
            source.get("hostname") or
            source.get("host_name")
        )
        if isinstance(host, dict):
            host = host.get("hostname") or host.get("name")
        if isinstance(host, list):
            host = host[0] if host else None

        # User
        user = (
            _f(source, "user.name") or
            source.get("user_name") or
            _f(source, "winlog.user.name")
        )
        if isinstance(user, dict):
            user = user.get("name")

        # Process context — ECS process.* fields
        process_name = (
            _f(source, "process.name")
            or _f(source, "process.executable")
            or _f(source, "winlog.event_data.Image")
        )
        if isinstance(process_name, dict):
            process_name = process_name.get("name")
        # Extract just the filename from a full path
        if process_name and ('\\' in str(process_name) or '/' in str(process_name)):
            process_name = str(process_name).rsplit('\\', 1)[-1].rsplit('/', 1)[-1]

        command_line = (
            _f(source, "process.command_line")
            or _f(source, "feature_command_line")
            or _f(source, "process.args")
            or _f(source, "winlog.event_data.CommandLine")
        )
        if isinstance(command_line, list):
            command_line = " ".join(str(a) for a in command_line)

        parent_process_name = (
            _f(source, "process.parent.name")
            or _f(source, "process.parent.executable")
            or _f(source, "winlog.event_data.ParentImage")
        )
        if isinstance(parent_process_name, dict):
            parent_process_name = parent_process_name.get("name")
        if parent_process_name and ('\\' in str(parent_process_name) or '/' in str(parent_process_name)):
            parent_process_name = str(parent_process_name).rsplit('\\', 1)[-1].rsplit('/', 1)[-1]

        # File context
        file_name = (
            _f(source, "file.name")
            or _f(source, "file.path")
            or _f(source, "winlog.event_data.TargetFilename")
        )
        file_path_val = _f(source, "file.path") or _f(source, "file.directory")
        file_hash = (
            _f(source, "file.hash.sha256")
            or _f(source, "file.hash.sha1")
            or _f(source, "file.hash.md5")
            or _f(source, "process.hash.sha256")
            or _f(source, "process.hash.md5")
        )
        if isinstance(file_hash, dict):
            file_hash = file_hash.get("sha256") or file_hash.get("sha1") or file_hash.get("md5")

        # Arkime PCAP linkage — `network.community_id` holds the Community ID
        # flow hash (shared between Zeek/Suricata/Arkime), and `node` carries
        # the Arkime capture node name. Both are required to hit Arkime's
        # `/api/session/{node}/{id}/pcap` endpoint.
        network_community_id = (
            _f(source, "network.community_id")
            or _f(source, "community_id")
            or source.get("network_community_id")
        )
        if isinstance(network_community_id, dict):
            network_community_id = (
                network_community_id.get("community_id")
                or network_community_id.get("id")
            )
        # broadened — `source.get("node")` only matched a flat
        # top-level key, missing the nested form ({"node": {...}} / dotted)
        # and the common ECS capture-appliance field `observer.hostname`.
        arkime_node = (
            _f(source, "node")
            or _f(source, "observer.name")
            or _f(source, "observer.hostname")
            or _f(source, "arkime.node")
        )
        if isinstance(arkime_node, dict):
            arkime_node = arkime_node.get("name") or arkime_node.get("hostname")
        # Normalise to strings
        if network_community_id is not None:
            network_community_id = str(network_community_id)
        if arkime_node is not None:
            arkime_node = str(arkime_node)

        # Source / destination IPs (ECS standard fields)
        source_ip = (
            _f(source, "source.ip")
            or _f(source, "client.ip")
            or source.get("src_ip")
        )
        if isinstance(source_ip, list):
            source_ip = source_ip[0] if source_ip else None
        destination_ip = (
            _f(source, "destination.ip")
            or _f(source, "server.ip")
            or source.get("dst_ip")
        )
        if isinstance(destination_ip, list):
            destination_ip = destination_ip[0] if destination_ip else None

        # Tags
        tags = source.get("tags", [])
        if isinstance(tags, str):
            tags = [tags]

        # P3b: Auto-tag from data_stream.namespace/dataset
        data_stream = source.get("data_stream", {})
        if isinstance(data_stream, dict):
            ds_namespace = data_stream.get("namespace")
            ds_dataset = data_stream.get("dataset")
            if ds_namespace and ds_namespace not in tags:
                tags.append(ds_namespace)
            if ds_dataset and ds_dataset not in tags:
                tags.append(ds_dataset)

        # P3a: Extract geo data from source/destination/client/server.
        # Arkime-fed alert docs carry only the 2-letter code
        # (source.geo.country_iso_code) — convert to a display name via the
        # static ISO map so geo doesn't silently vanish on those alerts.
        from ion.services.country_mapper import get_country_name

        # NOT the module-level _first — a later nested def in this method
        # shadows that name for the whole function scope.
        def _scalar(v):
            if isinstance(v, (list, tuple)):
                return v[0] if v else None
            return v

        geo_data = {}
        for prefix in ("source", "destination", "client", "server"):
            country = _scalar(_proc_field(source, f"{prefix}.geo.country_name"))
            iso_code = _scalar(_proc_field(source, f"{prefix}.geo.country_iso_code"))
            city = _scalar(_proc_field(source, f"{prefix}.geo.city_name"))
            location = _proc_field(source, f"{prefix}.geo.location")  # {lat, lon}
            if not country and iso_code:
                country = get_country_name(iso_code)
            if country:
                geo_data[f"{prefix}_country"] = country
            if iso_code:
                geo_data[f"{prefix}_country_iso_code"] = str(iso_code).upper()
            if city:
                geo_data[f"{prefix}_city"] = city
            if isinstance(location, dict) and location.get("lat") is not None:
                geo_data[f"{prefix}_lat"] = location["lat"]
                geo_data[f"{prefix}_lon"] = location["lon"]
            # AS organization — Arkime writes the combined "AS15169 Google LLC"
            # in {prefix}.as.full; ECS-standard docs use as.organization.name.
            as_org = _scalar(_proc_field(
                source, f"{prefix}.as.full", f"{prefix}.as.organization.name"
            ))
            if as_org:
                geo_data[f"{prefix}_as_org"] = str(as_org)

        # Source system from data_stream
        source_system = None
        if isinstance(data_stream, dict) and data_stream.get("namespace"):
            source_system = data_stream.get("namespace")

        # Rule name
        rule_name = (
            _f(source, "kibana.alert.rule.name") or
            _f(source, "signal.rule.name") or
            _f(source, "rule.name") or
            source.get("rule_name")
        )

        # MITRE ATT&CK fields
        # Helper to unwrap list-or-scalar values (ES may store as ["Impact"] or "Impact")
        def _first(val):
            if isinstance(val, list) and val:
                return val[0]
            return val

        # Primary path: nested threat object (ECS format)
        # Elastic Security 8.x stores threat as an array; older/custom as a dict
        threat = source.get("threat", {})
        mitre_technique_id = None
        mitre_technique_name = None
        mitre_tactic_name = None

        # Unwrap array → first element (Elastic Security 8.x detection alerts)
        if isinstance(threat, list) and threat:
            threat = threat[0]

        if isinstance(threat, dict) and threat:
            technique = threat.get("technique", {})
            tactic = threat.get("tactic", {})
            if isinstance(technique, dict):
                mitre_technique_id = _first(technique.get("id"))
                mitre_technique_name = _first(technique.get("name"))
            elif isinstance(technique, list) and technique:
                first_tech = technique[0] if isinstance(technique[0], dict) else {}
                mitre_technique_id = _first(first_tech.get("id"))
                mitre_technique_name = _first(first_tech.get("name"))
                # Check for subtechnique (more specific)
                subtechniques = first_tech.get("subtechnique", [])
                if isinstance(subtechniques, list) and subtechniques:
                    sub = subtechniques[0] if isinstance(subtechniques[0], dict) else {}
                    if sub.get("id"):
                        mitre_technique_id = _first(sub.get("id"))
                        mitre_technique_name = _first(sub.get("name")) or mitre_technique_name
            if isinstance(tactic, dict):
                mitre_tactic_name = _first(tactic.get("name"))
            elif isinstance(tactic, list) and tactic:
                first_tactic = tactic[0] if isinstance(tactic[0], dict) else {}
                mitre_tactic_name = _first(first_tactic.get("name"))

        # Fallback: dot-notation keys (Kibana Security alert format).
        # Try multiple key patterns — ES 8.x/9.x use different ones.
        for tid_key in ("threat.technique.id", "kibana.alert.rule.threat.technique.id"):
            if not mitre_technique_id:
                mitre_technique_id = _first(_f(source, tid_key))
        for tname_key in ("threat.technique.name", "kibana.alert.rule.threat.technique.name"):
            if not mitre_technique_name:
                mitre_technique_name = _first(_f(source, tname_key))
        for tactic_key in ("threat.tactic.name", "threat.tactic.id", "kibana.alert.rule.threat.tactic.name", "kibana.alert.rule.threat.tactic.id"):
            if not mitre_tactic_name:
                val = _first(_f(source, tactic_key))
                if val:
                    # tactic.id values look like "credential-access" — convert to display form
                    mitre_tactic_name = val.replace("_", " ").replace("-", " ").title() if "-" in str(val) or "_" in str(val) else val

        # Fallback: kibana.alert.rule.threat (Elastic Security — some versions)
        # and kibana.alert.rule.parameters.threat (other versions).
        # Both store the MITRE mapping as an array of {tactic, technique} objects.
        # Fallback: kibana.alert.rule.threat / kibana.alert.rule.parameters.threat
        # These are arrays with one entry PER tactic the rule maps to. The
        # technique is usually on the first entry but the tactic name may be
        # on any entry (often the last). We scan ALL entries.
        for threat_path in (
            "kibana.alert.rule.threat",
            "kibana.alert.rule.parameters.threat",
        ):
            if mitre_technique_id and mitre_tactic_name:
                break
            params_threat = _f(source, threat_path, [])
            if not isinstance(params_threat, list) or not params_threat:
                continue
            for pt in params_threat:
                if not isinstance(pt, dict):
                    continue
                # Extract technique from this entry
                pt_techniques = pt.get("technique", [])
                if isinstance(pt_techniques, list) and pt_techniques and not mitre_technique_id:
                    pt_tech = pt_techniques[0] if isinstance(pt_techniques[0], dict) else {}
                    mitre_technique_id = _first(pt_tech.get("id"))
                    mitre_technique_name = _first(pt_tech.get("name"))
                    # Check subtechniques (more specific)
                    pt_subs = pt_tech.get("subtechnique", [])
                    if isinstance(pt_subs, list) and pt_subs:
                        pt_sub = pt_subs[0] if isinstance(pt_subs[0], dict) else {}
                        if pt_sub.get("id"):
                            mitre_technique_id = _first(pt_sub.get("id"))
                            mitre_technique_name = _first(pt_sub.get("name")) or mitre_technique_name
                # Extract tactic from this entry
                if not mitre_tactic_name:
                    pt_tactic = pt.get("tactic", {})
                    if isinstance(pt_tactic, dict):
                        tactic_val = (
                            _first(pt_tactic.get("name"))
                            or _first(pt_tactic.get("id"))
                            or _first(pt_tactic.get("reference"))
                        )
                        if tactic_val:
                            # Handle URLs: "https://attack.mitre.org/tactics/TA0006/"
                            if "/" in str(tactic_val):
                                tactic_val = str(tactic_val).rstrip("/").rsplit("/", 1)[-1]
                            # Handle slug IDs: "credential-access" or "TA0006"
                            if "-" in str(tactic_val) or "_" in str(tactic_val):
                                tactic_val = str(tactic_val).replace("-", " ").replace("_", " ").title()
                            mitre_tactic_name = tactic_val

        # Fallback: signal.rule.threat[0].technique[0] (Elastic SIEM format)
        if not mitre_technique_id:
            signal_threats = _f(source, "signal.rule.threat", [])
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

        # Last resort: deep scan ALL keys in _source for any value matching T####
        # This catches custom/vendor-specific fields that store MITRE technique IDs
        # under non-standard key names.
        if not mitre_technique_id:
            import re as _re
            _tid_pattern = _re.compile(r'^T\d{4}(?:\.\d{3})?$')
            for key, val in source.items():
                if isinstance(val, str) and _tid_pattern.match(val):
                    mitre_technique_id = val
                    break
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, str) and _tid_pattern.match(item):
                            mitre_technique_id = item
                            break
                    if mitre_technique_id:
                        break

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
            geo_data=geo_data,
            source_system=source_system,
            network_community_id=network_community_id,
            arkime_node=arkime_node,
            source_ip=source_ip,
            destination_ip=destination_ip,
            process_name=process_name,
            command_line=command_line,
            parent_process_name=parent_process_name,
            file_name=file_name,
            file_hash=file_hash,
            file_path=file_path_val,
        )

    async def get_building_blocks(self, alert_id: str) -> List[Dict[str, Any]]:
        """Fetch building block alerts for an EQL sequence/correlation alert.

        EQL alerts store the real event data (process, file, network) in
        child "building block" documents linked by ``kibana.alert.group.id``.
        The parent alert only has the correlation metadata.

        Returns a list of parsed event dicts sorted by timestamp, or an
        empty list if the alert is not an EQL alert or has no blocks.
        """
        try:
            # First get the parent alert to find its group.id
            parent_result = await self._request(
                "POST",
                f"/{self.alert_index}/_search"
                "?ignore_unavailable=true&expand_wildcards=open,hidden",
                json={
                    "size": 1,
                    "query": {"ids": {"values": [alert_id]}},
                    "_source": [
                        "kibana.alert.group.id",
                        "kibana.alert.rule.type",
                    ],
                },
            )
            hits = parent_result.get("hits", {}).get("hits", [])
            if not hits:
                return []

            source = hits[0].get("_source", {})
            _f = self._get_field
            group_id = _f(source, "kibana.alert.group.id")
            rule_type = _f(source, "kibana.alert.rule.type")

            if not group_id:
                return []

            # Fetch all building blocks sharing this group.id
            bb_result = await self._request(
                "POST",
                f"/{self.alert_index}/_search"
                "?ignore_unavailable=true&expand_wildcards=open,hidden",
                json={
                    "size": 100,
                    "sort": [{"@timestamp": {"order": "asc"}}],
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"kibana.alert.group.id": group_id}},
                                {"exists": {"field": "kibana.alert.building_block_type"}},
                            ]
                        }
                    },
                },
            )

            blocks = []
            for hit in bb_result.get("hits", {}).get("hits", []):
                src = hit.get("_source", {})
                block = {
                    "id": hit.get("_id"),
                    "timestamp": src.get("@timestamp"),
                    "rule_name": _f(src, "kibana.alert.rule.name") or _f(src, "rule.name"),
                    "host": _f(src, "host.hostname") or _f(src, "host.name"),
                    "user": _f(src, "user.name"),
                    "process_name": _f(src, "process.name"),
                    "command_line": (
                        _f(src, "process.command_line")
                        or _f(src, "feature_command_line")
                        or _f(src, "winlog.event_data.CommandLine")
                    ),
                    "parent_process": _f(src, "process.parent.name"),
                    "file_name": _f(src, "file.name") or _f(src, "file.path"),
                    "file_hash": (
                        _f(src, "file.hash.sha256")
                        or _f(src, "file.hash.md5")
                    ),
                    "source_ip": _f(src, "source.ip"),
                    "destination_ip": _f(src, "destination.ip"),
                    "event_action": _f(src, "event.action"),
                }
                # Handle list values
                for k in ("process_name", "command_line", "source_ip", "destination_ip"):
                    if isinstance(block[k], list):
                        block[k] = block[k][0] if block[k] else None
                blocks.append(block)

            return blocks

        except ElasticsearchError as e:
            logger.warning("Failed to fetch building blocks for %s: %s", alert_id, e)
            return []

    async def resolve_process_event_docs(
        self, entity_ids: List[str], parent_entity_id: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Resolve process-event ``_source`` docs from the configured events index.

        Used by the full process explorer to (a) name the ancestry chain by
        ``process.entity_id`` and (b) find the alert process's direct children by
        ``process.parent.entity_id``. Returns ``[]`` when no events index is
        configured or on any query error — the caller then falls back to the
        alert-local tree.
        """
        if not self.process_events_index:
            return []
        should: List[Dict[str, Any]] = []
        ids = [e for e in (entity_ids or []) if e]
        if ids:
            should.append({"terms": {"process.entity_id": ids}})
        if parent_entity_id:
            should.append({"term": {"process.parent.entity_id": parent_entity_id}})
        if not should:
            return []
        try:
            result = await self._request(
                "POST",
                f"/{self.process_events_index}/_search"
                "?ignore_unavailable=true&expand_wildcards=open,hidden",
                json={
                    "size": 200,
                    "sort": [{"@timestamp": {"order": "asc"}}],
                    "_source": [
                        "process.name", "process.executable", "process.pid",
                        "process.entity_id", "process.command_line",
                        "process.parent.entity_id", "process.user.name", "user.name",
                    ],
                    "query": {"bool": {"should": should, "minimum_should_match": 1}},
                },
            )
            return [
                hit.get("_source", {})
                for hit in result.get("hits", {}).get("hits", [])
                if hit.get("_source")
            ]
        except ElasticsearchError as e:
            # Log only the exception TYPE. Neither the exception body (can carry
            # the request URL/auth) nor self.* config-derived values (CodeQL taints
            # them from the same config that holds the ES password) may be logged —
            # py/clear-text-logging-sensitive-data.
            logger.warning("Process-event resolution failed (%s)", type(e).__name__)
            return []

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
            logger.error("Error fetching alerts by ID: %s", e)
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
            logger.warning("Failed to index case %s to Elasticsearch: %s", case_id, type(e).__name__)
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
            logger.warning("Failed to delete case %s from Elasticsearch: %s", case_id, type(e).__name__)
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
            logger.warning("Failed to index KFP %s to Elasticsearch: %s", kfp_id, type(e).__name__)
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
            logger.warning("Failed to delete KFP %s from Elasticsearch: %s", kfp_id, type(e).__name__)
            return False

    # ION triage status → Kibana alert workflow_status mapping (1:1 now)
    _WORKFLOW_STATUS_MAP = {
        "open": "open",
        "acknowledged": "acknowledged",
        "closed": "closed",
    }

    async def update_alert_workflow_status(
        self,
        alert_ids: List[str],
        ion_status: str,
    ) -> bool:
        """Update alert workflow_status in Elasticsearch/Kibana.

        Strategy:
        1. Try Kibana Detection Engine API (POST /api/detection_engine/signals/status)
           — this is required for .alerts-* (Kibana Security) indices which are write-protected.
        2. Fall back to direct ES _update_by_query for non-Kibana alerts (watcher, custom).

        Returns True on success, False on failure (logs warning, does not raise).
        """
        workflow_status = self._WORKFLOW_STATUS_MAP.get(ion_status)
        if not workflow_status:
            logger.warning("No workflow_status mapping for ION status: %s", ion_status)
            return False

        if not alert_ids:
            return True

        # Try both Kibana API (for .alerts-* indices) and ES direct (for custom indices)
        kibana_ok = await self._update_via_kibana_api(alert_ids, workflow_status)
        es_ok = await self._update_via_es_direct(alert_ids, workflow_status)

        # Return True if either succeeded
        return kibana_ok or es_ok

    async def _update_via_kibana_api(
        self,
        alert_ids: List[str],
        workflow_status: str,
    ) -> bool:
        """Update alert status via Kibana's Detection Engine API.

        POST /api/detection_engine/signals/status
        Body: { "signal_ids": [...], "status": "open|acknowledged|closed" }

        This is the only reliable way to update .alerts-* (Kibana Security) indices.
        """
        try:
            from ion.core.config import get_kibana_config, get_ssl_verify
            kibana_config = get_kibana_config()

            # Use Kibana URL if configured, otherwise try deriving from ES URL
            # (ES on :9200 often means Kibana on :5601 at the same host)
            kibana_url = kibana_config.get("url", "").rstrip("/") if kibana_config.get("url") else ""
            if not kibana_url and self.url:
                # Derive Kibana URL from Elasticsearch URL (swap port 9200 → 5601)
                import re
                # self.url has already been redacted of credentials in __init__,
                # but use _redact_url defensively when logging.
                kibana_url = re.sub(r":9\d{3}$", ":5601", self.url)
                if kibana_url == self.url:
                    # Couldn't derive — ES isn't on a 9xxx port
                    logger.debug("Cannot derive Kibana URL from ES URL: %s", _redact_url(self.url))
                    return False
                logger.debug("Derived Kibana URL from ES URL: %s", _redact_url(kibana_url))

            if not kibana_url:
                logger.debug("No Kibana URL available, skipping Kibana API for workflow_status")
                return False

            space_id = kibana_config.get("space_id", "default") if kibana_config.get("enabled") else "default"
            space_prefix = f"/s/{space_id}" if space_id and space_id != "default" else ""

            # Try both old (8.x) and new (9.x) API paths
            api_paths = [
                f"{space_prefix}/api/detection_engine/signals/status",
                f"{space_prefix}/api/detection_engine/alerts/status",
            ]

            # Use Kibana auth if available, otherwise fall back to ES credentials
            auth = None
            kb_user = kibana_config.get("username") if kibana_config.get("enabled") else None
            kb_pass = kibana_config.get("password") if kibana_config.get("enabled") else None
            if kb_user and kb_pass:
                auth = (kb_user, kb_pass)
            elif self.username and self.password:
                auth = (self.username, self.password)

            body = {
                "signal_ids": alert_ids,
                "status": workflow_status,
                "conflicts": "proceed",
            }

            verify_ssl = kibana_config.get("verify_ssl", True) if kibana_config.get("enabled") else self.verify_ssl
            async with httpx.AsyncClient(
                auth=auth,
                verify=get_ssl_verify(verify_ssl),
                timeout=httpx.Timeout(30.0, connect=10.0),
            ) as client:
                for api_path in api_paths:
                    response = await client.post(
                        f"{kibana_url}{api_path}",
                        json=body,
                        headers={
                            "kbn-xsrf": "true",
                            "Content-Type": "application/json",
                        },
                    )
                    if response.status_code == 200:
                        # Avoid putting fields tied to credentialed-request data into a
                        # format string sensitive to taint analysis.
                        status_label = str(workflow_status)
                        count = len(alert_ids)
                        logger.info(
                            "Updated workflow_status for %d alerts via Kibana API (status=%s)",
                            count, status_label,
                        )
                        return True
                    # Do NOT log response.text — Kibana 401/403 bodies can echo
                    # auth headers / cookies. Status code is enough to debug.
                    logger.warning(
                        "Kibana API workflow_status update: %s returned %d for %d alerts (status=%s)",
                        api_path, response.status_code, len(alert_ids), workflow_status,
                    )

            return False

        except Exception as e:
            logger.warning("Kibana API workflow_status update failed: %s", type(e).__name__)
            return False

    async def _update_via_es_direct(
        self,
        alert_ids: List[str],
        workflow_status: str,
    ) -> bool:
        """Fallback: update workflow_status via direct ES _update_by_query.

        Works for watcher alerts, custom alert indices, and any non-Kibana-managed index.
        """
        try:
            body = {
                "query": {"ids": {"values": alert_ids}},
                "script": {
                    "source": (
                        "ctx._source['kibana.alert.workflow_status'] = params.status; "
                        "if (ctx._source.kibana == null) { ctx._source.kibana = new HashMap(); } "
                        "if (ctx._source.kibana.alert == null) { ctx._source.kibana.alert = new HashMap(); } "
                        "ctx._source.kibana.alert.workflow_status = params.status; "
                        "ctx._source.status = params.status;"
                    ),
                    "lang": "painless",
                    "params": {"status": workflow_status},
                },
            }
            # Use comma-separated index pattern directly (no URL encoding needed)
            result = await self._request(
                "POST",
                f"/{self.alert_index}/_update_by_query?conflicts=proceed&ignore_unavailable=true&expand_wildcards=open,hidden",
                json=body,
            )
            updated = result.get("updated", 0)
            logger.info(
                "Updated workflow_status to '%s' for %d/%d alerts via ES direct",
                workflow_status, updated, len(alert_ids),
            )
            return True
        except ElasticsearchError as e:
            logger.warning(
                "Failed to update alert workflow_status in ES: %s", e,
            )
            return False

    async def update_alert(self, alert_id: str, fields: Dict[str, Any]) -> bool:
        """Set arbitrary dotted-path fields on an alert document.

        Used by the autonomous investigation loop to persist verdict/severity/
        MITRE-tag metadata under the `ion.*` namespace.
        Returns True on success, False on failure (logs warning, does not raise).
        """
        if not alert_id or not fields:
            return False

        set_lines: List[str] = []
        params: Dict[str, Any] = {}
        for idx, (path, value) in enumerate(fields.items()):
            param_name = f"v{idx}"
            params[param_name] = value
            parts = path.split(".")
            ensure_lines = []
            current_ref = "ctx._source"
            for depth in range(len(parts) - 1):
                current_ref = f"{current_ref}['{parts[depth]}']"
                ensure_lines.append(
                    f"if ({current_ref} == null) {{ {current_ref} = new HashMap(); }}"
                )
            set_lines.extend(ensure_lines)
            leaf_ref = "ctx._source" + "".join(f"['{p}']" for p in parts)
            set_lines.append(f"{leaf_ref} = params.{param_name};")

        script_source = " ".join(set_lines)
        body = {
            "query": {"ids": {"values": [alert_id]}},
            "script": {
                "source": script_source,
                "lang": "painless",
                "params": params,
            },
        }

        try:
            result = await self._request(
                "POST",
                f"/{self.alert_index}/_update_by_query"
                "?conflicts=proceed&ignore_unavailable=true&expand_wildcards=open,hidden",
                json=body,
            )
            updated = result.get("updated", 0)
            if updated >= 1:
                logger.debug("update_alert: set %d fields on %s", len(fields), alert_id)
                return True
            logger.warning(
                "update_alert: no documents updated for %s", alert_id,
            )
            return False
        except ElasticsearchError as e:
            logger.warning("update_alert failed for %s: %s", alert_id, e)
            return False

    # =========================================================================
    # User Mapping for Alert Assignment
    # =========================================================================

    @property
    def user_mapping_configured(self) -> bool:
        """Check if ES user mapping is configured."""
        return bool(self.user_index) and bool(self.user_field)

    async def get_assignment_users(self, search: str = "", force_refresh: bool = False) -> List[Dict[str, str]]:
        """Fetch user names from the configured ES user index.

        Returns a list of {"name": "...", "value": "..."} for the assignment dropdown.
        Handles both plain keyword fields and multi-fields (text + .keyword).

        Results are cached in memory (5 min TTL).  If ES is unreachable the
        stale cache is returned so the UI still works.
        """
        global _assignment_users_cache, _assignment_users_cached_at

        if not self.is_configured or not self.user_mapping_configured:
            return []

        # Return cached list for non-search requests when cache is fresh
        now = datetime.utcnow()
        cache_valid = (
            _assignment_users_cached_at is not None
            and (now - _assignment_users_cached_at) < _ASSIGNMENT_CACHE_TTL
            and not force_refresh
        )

        if cache_valid and not search:
            return list(_assignment_users_cache)

        # If searching against a fresh cache, filter in-memory (no ES round-trip)
        if cache_valid and search:
            term = search.lower()
            return [u for u in _assignment_users_cache if term in u["name"].lower()]

        # Cache miss or expired — fetch from ES
        try:
            users = await self._fetch_users_from_es(search)

            # Only update the full cache on non-search (complete) fetches
            if not search:
                _assignment_users_cache = users
                _assignment_users_cached_at = now
                # Use a fresh local int and log without referencing self attributes
                # tied to the credentialed request path (CodeQL taint propagation).
                user_count = len(users)
                logger.info("Refreshed assignment users cache: %d users", user_count)

            return users

        except ElasticsearchError as e:
            logger.warning("Failed to fetch assignment users from ES: %s", e)
            # Return stale cache if available (graceful degradation)
            if _assignment_users_cache:
                logger.info("Returning stale assignment users cache (%d users)", len(_assignment_users_cache))
                if search:
                    term = search.lower()
                    return [u for u in _assignment_users_cache if term in u["name"].lower()]
                return list(_assignment_users_cache)
            return []

    @staticmethod
    def invalidate_assignment_cache():
        """Clear the assignment users cache (e.g. after config change)."""
        global _assignment_users_cache, _assignment_users_cached_at
        _assignment_users_cache = []
        _assignment_users_cached_at = None

    async def _fetch_users_from_es(self, search: str = "") -> List[Dict[str, str]]:
        """Query ES for assignment users."""
        body: Dict[str, Any] = {"size": 200}
        kw_field = self.user_field + ".keyword"

        if search:
            body["query"] = {
                "bool": {
                    "should": [
                        {"wildcard": {kw_field: {"value": f"*{search}*", "case_insensitive": True}}},
                        {"wildcard": {self.user_field: {"value": f"*{search}*", "case_insensitive": True}}},
                        {"match": {self.user_field: {"query": search, "fuzziness": "AUTO"}}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        else:
            body["query"] = {"match_all": {}}

        body["sort"] = [{kw_field: {"order": "asc", "unmapped_type": "keyword"}}]
        body["_source"] = [self.user_field]

        result = await self._request(
            "POST",
            f"/{self.user_index}/_search",
            json=body,
        )

        users = []
        seen = set()
        for hit in result.get("hits", {}).get("hits", []):
            source = hit.get("_source", {})
            value = source
            for part in self.user_field.split("."):
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    value = None
                    break

            if value and isinstance(value, str) and value not in seen:
                seen.add(value)
                users.append({"name": value, "value": value})

        return users

    async def update_alert_assignment(
        self,
        alert_ids: List[str],
        assigned_user: Optional[str],
    ) -> bool:
        """Write the assigned user name to the configured field on alert documents in ES."""
        if not self.is_configured or not self.assignment_field:
            return False

        try:
            field = self.assignment_field
            if assigned_user:
                # Set the assignment field
                script_source = (
                    f"ctx._source['{field}'] = params.user; "
                )
                # Also handle nested dotted fields (e.g., kibana.alert.workflow_user)
                parts = field.split(".")
                if len(parts) > 1:
                    nested_lines = []
                    for i in range(len(parts) - 1):
                        path = ".".join(parts[:i + 1])
                        accessor = "ctx._source" + "".join(f"['{p}']" for p in parts[:i + 1])
                        nested_lines.append(
                            f"if ({accessor} == null) {{ {accessor} = new HashMap(); }}"
                        )
                    nested_accessor = "ctx._source" + "".join(f"['{p}']" for p in parts)
                    nested_lines.append(f"{nested_accessor} = params.user;")
                    script_source = " ".join(nested_lines)

                params = {"user": assigned_user}
            else:
                # Clear the assignment field
                script_source = f"ctx._source.remove('{field}'); "
                parts = field.split(".")
                if len(parts) > 1:
                    nested_accessor = "ctx._source" + "".join(f"['{p}']" for p in parts[:-1])
                    script_source = (
                        f"if ({nested_accessor} != null) {{ {nested_accessor}.remove('{parts[-1]}'); }}"
                    )
                params = {}

            body = {
                "query": {"ids": {"values": alert_ids}},
                "script": {
                    "source": script_source,
                    "lang": "painless",
                    "params": params,
                },
            }

            result = await self._request(
                "POST",
                f"/{self.alert_index}/_update_by_query?conflicts=proceed&ignore_unavailable=true&expand_wildcards=open,hidden",
                json=body,
            )
            updated = result.get("updated", 0)
            logger.info(
                "Updated assignment to '%s' for %d/%d alerts in ES",
                assigned_user or "(unassigned)", updated, len(alert_ids),
            )
            return True

        except ElasticsearchError as e:
            logger.warning("Failed to update alert assignment in ES: %s", e)
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
            indices = await self._list_indices_cat(pattern, include_system, include_stats)
        except ElasticsearchError as e:
            # /_cat/indices requires monitor privilege; fall back to
            # _resolve/index which only needs view_index_metadata
            if "403" in str(e) or "security_exception" in str(e).lower() or "unauthorized" in str(e).lower():
                try:
                    indices = await self._list_indices_resolve(pattern, include_system)
                except ElasticsearchError as e2:
                    return {"error": str(e2), "indices": []}
            else:
                return {"error": str(e), "indices": []}

        indices.sort(key=lambda x: x["name"])
        return {"indices": indices, "total": len(indices)}

    async def _list_indices_cat(
        self,
        pattern: str,
        include_system: bool,
        include_stats: bool,
    ) -> list:
        """List indices via /_cat/indices (requires monitor privilege)."""
        if include_stats:
            result = await self._request("GET", f"/_cat/indices/{pattern}?format=json&h=index,health,status,docs.count,store.size,creation.date")
        else:
            result = await self._request("GET", f"/_cat/indices/{pattern}?format=json&h=index,health,status")

        indices = []
        for idx in result:
            index_name = idx.get("index", "")
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
        return indices

    async def _list_indices_resolve(
        self,
        pattern: str,
        include_system: bool,
    ) -> list:
        """Fallback: list indices via _resolve/index (lower privilege)."""
        result = await self._request("GET", f"/_resolve/index/{pattern}")
        indices = []
        for idx in result.get("indices", []):
            index_name = idx.get("name", "")
            if not include_system and index_name.startswith("."):
                continue
            # Try to get doc count via a count query per index
            doc_count = 0
            try:
                count_result = await self._request("GET", f"/{index_name}/_count")
                doc_count = count_result.get("count", 0)
            except ElasticsearchError:
                pass
            indices.append({
                "name": index_name,
                "health": None,
                "status": "open",
                "doc_count": doc_count,
                "size": None,
            })
        return indices

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

        # Email — use a structural check rather than a polynomial regex
        # (the previous `^[^@]+@[^@]+\.[^@]+$` had overlapping `[^@]+` groups
        #  which caused catastrophic backtracking on adversarial input).
        if (
            value
            and value.count('@') == 1
            and ' ' not in value
            and len(value) <= 320
        ):
            local, _, domain = value.partition('@')
            if local and domain and '.' in domain and not domain.startswith('.') and not domain.endswith('.'):
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

    # =========================================================================
    # Engineering System Analytics
    # =========================================================================

    async def get_alert_rollup_for_namespaces(
        self,
        namespaces: List[str],
        hours: int = 168,
    ) -> Dict[str, Any]:
        """Return alert counts for a specific list of `data_stream.namespace` values.

        Used by the CyAB system detail page to show "open alerts: N (last 7d)"
        scoped to the namespaces owned by that CyAB system. Single ES query
        with a `terms` filter + status sub-aggregation.

        Returns:
            {
                "total": int,
                "by_status": {open: N, acknowledged: N, closed: N},
                "by_severity": {critical: N, high: N, medium: N, low: N},
                "by_namespace": {ns: count, ...},
                "hours": int,
            }
        """
        empty: Dict[str, Any] = {
            "total": 0,
            "by_status": {},
            "by_severity": {},
            "by_namespace": {},
            "hours": hours,
        }
        if not self.is_configured or not namespaces:
            return empty

        # Lowercase the input — ES stores namespaces lowercase by convention
        ns_clean = sorted({(n or "").strip().lower() for n in namespaces if n})
        if not ns_clean:
            return empty

        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}},
                        {"terms": {"data_stream.namespace": ns_clean}},
                    ],
                    "must_not": [
                        {"exists": {"field": "kibana.alert.building_block_type"}},
                    ],
                }
            },
            "aggs": {
                "by_status": {
                    "terms": {"field": "kibana.alert.workflow_status", "size": 10, "missing": "open"}
                },
                "by_severity": {
                    "terms": {"field": "kibana.alert.severity", "size": 10, "missing": "unknown"}
                },
                "by_namespace": {
                    "terms": {"field": "data_stream.namespace", "size": len(ns_clean)}
                },
            },
        }

        try:
            result = await self._request(
                "POST",
                f"/{self.alert_index}/_search",
                json=query,
            )
        except ElasticsearchError as e:
            if "index_not_found" in str(e).lower() or "404" in str(e):
                return empty
            raise

        total = result.get("hits", {}).get("total", {})
        if isinstance(total, dict):
            total = total.get("value", 0)

        def _bucket_dict(agg):
            return {b["key"]: b["doc_count"] for b in (agg or {}).get("buckets", [])}

        aggs = result.get("aggregations", {})
        return {
            "total": int(total or 0),
            "by_status": _bucket_dict(aggs.get("by_status")),
            "by_severity": _bucket_dict(aggs.get("by_severity")),
            "by_namespace": _bucket_dict(aggs.get("by_namespace")),
            "hours": hours,
        }

    async def get_system_analytics(
        self,
        hours: int = 24,
        index_pattern: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Aggregate alert/event metrics per system using data_stream.namespace and _index.

        Uses ES aggregations so all computation happens server-side.
        Returns per-system alert counts, severity breakdown, top rules, and time histograms.
        """
        if not self.is_configured:
            return {"error": "Elasticsearch is not configured", "systems": []}

        pattern = index_pattern or self.alert_index

        # Pick histogram interval based on window
        if hours <= 6:
            interval = "15m"
        elif hours <= 48:
            interval = "1h"
        elif hours <= 168:
            interval = "6h"
        else:
            interval = "1d"

        query = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}}
                    ],
                    "must_not": [
                        {"term": {"kibana.alert.building_block_type": "default"}}
                    ]
                }
            },
            "aggs": {
                # Primary aggregation: by data_stream.namespace
                "by_namespace": {
                    "terms": {"field": "data_stream.namespace", "size": 50, "missing": "_unknown_"},
                    "aggs": {
                        "by_severity": {
                            "terms": {"field": "kibana.alert.severity", "size": 10, "missing": "unknown"}
                        },
                        "by_status": {
                            "terms": {"field": "kibana.alert.workflow_status", "size": 10, "missing": "open"}
                        },
                        "top_rules": {
                            "terms": {"field": "kibana.alert.rule.name", "size": 10}
                        },
                        "over_time": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": interval,
                                "min_doc_count": 0,
                                "extended_bounds": {
                                    "min": f"now-{hours}h",
                                    "max": "now"
                                }
                            }
                        },
                        "unique_hosts": {
                            "cardinality": {"field": "host.name"}
                        },
                        "unique_users": {
                            "cardinality": {"field": "user.name"}
                        },
                        "by_dataset": {
                            "terms": {"field": "data_stream.dataset", "size": 20}
                        }
                    }
                },
                # Secondary: by index name (captures non-data-stream indices)
                "by_index": {
                    "terms": {"field": "_index", "size": 50},
                    "aggs": {
                        "by_severity": {
                            "terms": {"field": "kibana.alert.severity", "size": 10, "missing": "unknown"}
                        }
                    }
                },
                # Overall severity breakdown
                "total_by_severity": {
                    "terms": {"field": "kibana.alert.severity", "size": 10, "missing": "unknown"}
                },
                # Overall time histogram
                "total_over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": interval,
                        "min_doc_count": 0,
                        "extended_bounds": {
                            "min": f"now-{hours}h",
                            "max": "now"
                        }
                    }
                }
            }
        }

        try:
            encoded = pattern.replace(",", "%2C")
            result = await self._request("POST", f"/{encoded}/_search", json=query)
        except ElasticsearchError as e:
            if "index_not_found" in str(e).lower():
                return {"systems": [], "indices": [], "total": 0, "error": None}
            return {"error": str(e), "systems": [], "indices": [], "total": 0}

        total = result.get("hits", {}).get("total", {})
        if isinstance(total, dict):
            total = total.get("value", 0)

        aggs = result.get("aggregations", {})

        # Parse namespace buckets into system entries
        systems = []
        ns_buckets = aggs.get("by_namespace", {}).get("buckets", [])
        for b in ns_buckets:
            namespace = b["key"]
            severity_map = {sb["key"]: sb["doc_count"] for sb in b.get("by_severity", {}).get("buckets", [])}
            status_map = {sb["key"]: sb["doc_count"] for sb in b.get("by_status", {}).get("buckets", [])}
            top_rules = [{"rule": rb["key"], "count": rb["doc_count"]} for rb in b.get("top_rules", {}).get("buckets", [])]
            timeline = [{"timestamp": tb["key_as_string"], "count": tb["doc_count"]} for tb in b.get("over_time", {}).get("buckets", [])]
            datasets = [{"dataset": db["key"], "count": db["doc_count"]} for db in b.get("by_dataset", {}).get("buckets", [])]

            systems.append({
                "system": namespace,
                "alert_count": b["doc_count"],
                "severity": severity_map,
                "status": status_map,
                "top_rules": top_rules,
                "timeline": timeline,
                "datasets": datasets,
                "unique_hosts": b.get("unique_hosts", {}).get("value", 0),
                "unique_users": b.get("unique_users", {}).get("value", 0),
            })

        # Sort by alert count descending
        systems.sort(key=lambda s: s["alert_count"], reverse=True)

        # Parse index buckets
        indices = []
        idx_buckets = aggs.get("by_index", {}).get("buckets", [])
        for b in idx_buckets:
            severity_map = {sb["key"]: sb["doc_count"] for sb in b.get("by_severity", {}).get("buckets", [])}
            indices.append({
                "index": b["key"],
                "count": b["doc_count"],
                "severity": severity_map,
            })
        indices.sort(key=lambda x: x["count"], reverse=True)

        # Total severity
        total_severity = {sb["key"]: sb["doc_count"] for sb in aggs.get("total_by_severity", {}).get("buckets", [])}

        # Total timeline
        total_timeline = [{"timestamp": tb["key_as_string"], "count": tb["doc_count"]} for tb in aggs.get("total_over_time", {}).get("buckets", [])]

        # Always fetch log-side per-namespace volumes so each system entry
        # carries both `alert_count` (from .alerts-*) and `logs_ingested`
        # (from logs-*). Two failure modes covered:
        #   1. Alerts use the default namespace but log data-streams are
        #      per-system named — the log query is the only way to discover
        #      systems at all (the original fallback case).
        #   2. Alerts produce multi-namespace data, but the operator wants
        #      the L1/L2 view to show *log volume* per system alongside
        #      alert volume — what System Analytics now does always.
        log_systems_map = {}
        log_total = 0
        try:
            log_systems = await self._discover_systems_from_logs(hours, interval)
            for ls in log_systems:
                ns = ls.get("system")
                if ns is None:
                    continue
                log_systems_map[ns] = {
                    "logs_ingested": ls.get("event_count", 0),
                    "logs_timeline": ls.get("timeline", []),
                    "logs_datasets": ls.get("datasets", []),
                    "logs_categories": ls.get("categories", []),
                    "logs_unique_hosts": ls.get("unique_hosts", 0),
                    "logs_unique_users": ls.get("unique_users", 0),
                }
                log_total += ls.get("event_count", 0)
        except Exception:
            pass  # Non-fatal — log enrichment is additive; alert data still ships

        # Merge log volumes into every alert-side system entry; if a
        # namespace exists in logs but had no alerts, surface it as a
        # zero-alert entry so it still appears in the UI.
        if log_systems_map:
            existing_ns = {s.get("system") for s in systems}
            for s in systems:
                ns = s.get("system")
                if ns in log_systems_map:
                    s.update(log_systems_map[ns])
            for ns, log_data in log_systems_map.items():
                if ns not in existing_ns and ns and ns != "_unknown_":
                    systems.append({
                        "system": ns,
                        "alert_count": 0,
                        "severity": {},
                        "status": {},
                        "top_rules": [],
                        "timeline": [],
                        "datasets": log_data.get("logs_datasets", []),
                        "unique_hosts": log_data.get("logs_unique_hosts", 0),
                        "unique_users": log_data.get("logs_unique_users", 0),
                        **log_data,
                    })
            # Re-sort: prefer alert volume, fall back to log volume
            systems.sort(key=lambda s: (s.get("alert_count", 0), s.get("logs_ingested", 0)), reverse=True)

        return {
            "systems": systems,
            "indices": indices,
            "total": total,
            "total_logs_ingested": log_total,
            "total_severity": total_severity,
            "total_timeline": total_timeline,
            "hours": hours,
            "interval": interval,
            "error": None,
        }

    async def _discover_systems_from_logs(self, hours: int, interval: str) -> List[Dict]:
        """Query logs-* directly to discover systems by data_stream.namespace.

        Kibana Security alerts live in .alerts-* with namespace='default',
        but the ORIGINAL events live in logs-*-<systemname> with per-system
        namespaces. This method queries the log indices to find all systems.
        """
        query = {
            "size": 0,
            "query": {
                "range": {"@timestamp": {"gte": f"now-{hours}h", "lte": "now"}}
            },
            "aggs": {
                "by_namespace": {
                    "terms": {"field": "data_stream.namespace", "size": 50},
                    "aggs": {
                        "by_dataset": {
                            "terms": {"field": "data_stream.dataset", "size": 20}
                        },
                        "over_time": {
                            "date_histogram": {
                                "field": "@timestamp",
                                "fixed_interval": interval,
                                "min_doc_count": 0,
                                "extended_bounds": {
                                    "min": f"now-{hours}h",
                                    "max": "now"
                                }
                            }
                        },
                        "unique_hosts": {
                            "cardinality": {"field": "host.name"}
                        },
                        "unique_users": {
                            "cardinality": {"field": "user.name"}
                        },
                        "by_event_category": {
                            "terms": {"field": "event.category", "size": 10}
                        },
                    }
                }
            }
        }

        try:
            result = await self._request(
                "POST",
                "/logs-*/_search",
                json=query,
            )
        except ElasticsearchError:
            return []

        systems = []
        for b in result.get("aggregations", {}).get("by_namespace", {}).get("buckets", []):
            namespace = b["key"]
            datasets = [
                {"dataset": db["key"], "count": db["doc_count"]}
                for db in b.get("by_dataset", {}).get("buckets", [])
            ]
            timeline = [
                {"timestamp": tb["key_as_string"], "count": tb["doc_count"]}
                for tb in b.get("over_time", {}).get("buckets", [])
            ]
            categories = [
                {"category": cb["key"], "count": cb["doc_count"]}
                for cb in b.get("by_event_category", {}).get("buckets", [])
            ]
            systems.append({
                "system": namespace,
                "event_count": b["doc_count"],
                "alert_count": 0,  # Will be filled by cross-ref later
                "severity": {},
                "status": {},
                "top_rules": [],
                "timeline": timeline,
                "datasets": datasets,
                "categories": categories,
                "unique_hosts": b.get("unique_hosts", {}).get("value", 0),
                "unique_users": b.get("unique_users", {}).get("value", 0),
                "source": "logs",
            })
        systems.sort(key=lambda s: s["event_count"], reverse=True)
        return systems
