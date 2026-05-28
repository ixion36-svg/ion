"""Arkime integration — resolve a Community ID flow hash to one or more
Arkime sessions and fetch the raw PCAP bytes.

Arkime 5.x exposes a PCAP download endpoint on the viewer:

    {base}/api/session/{node}/{sessionId}/pcap

where `{node}` is the capture node identifier (Arkime node name) and
`{sessionId}` is Arkime's internal session id. Alerts don't carry the Arkime
session id directly — they carry `network.community_id` (the Community ID
flow hash shared between Zeek/Suricata/Arkime) and `node` (the capture node).
So the flow is always two hops:

    1. Look up sessions by Community ID + node via `/api/sessions?expression=...`
    2. Download the PCAP for each matching session id

There can legitimately be multiple Arkime sessions matching one Community ID
(a long-running flow, or sessions split across rotation windows), so
`download_pcap_by_community_id` returns the FIRST match with a list of any
additional matches in the metadata.

Authentication: HTTP Basic only (v0.10.4+). Configure via:

    ION_ARKIME_URL=https://arkime.example.com
    ION_ARKIME_USERNAME=admin
    ION_ARKIME_PASSWORD=password
    ION_ARKIME_VERIFY_SSL=true|false
"""

from __future__ import annotations

import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from ion.core.config import get_arkime_config


def _parse_alert_epoch(ts: Any) -> Optional[int]:
    """Best-effort parse of an alert timestamp into epoch seconds.

    ES uses ISO 8601 with a trailing Z (``2026-04-23T08:05:24.140Z``).
    Returns None for anything we can't parse — callers fall back to a
    now-anchored window in that case.
    """
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return int(ts)
    if isinstance(ts, str):
        try:
            normalized = ts.replace("Z", "+00:00")
            return int(datetime.fromisoformat(normalized).timestamp())
        except (ValueError, TypeError):
            return None
    return None


def _env_int(name: str, default: int) -> int:
    """Read an int env var; fall back to default on missing/malformed."""
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    """Read a float env var; fall back to default on missing/malformed."""
    try:
        return float(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default

logger = logging.getLogger(__name__)


class ArkimeError(Exception):
    """Raised for any Arkime viewer API failure."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class ArkimeService:
    """Thin async client for the Arkime viewer API.

    Auth: **Basic only.** v0.10.4 locks Arkime to HTTP Basic auth via an
    explicit ``Authorization: Basic <base64>`` header. Digest and API-key
    flows were removed — they were prone to challenge/response issues
    behind proxies and mixed-auth setups. If your Arkime deployment requires
    something else, front it with nginx + Basic.

    Configuration (.env):
        ION_ARKIME_URL=https://arkime.example.com
        ION_ARKIME_USERNAME=admin
        ION_ARKIME_PASSWORD=password
        ION_ARKIME_VERIFY_SSL=false
    """

    def __init__(
        self,
        url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        **_kwargs,  # Accept and ignore legacy api_key / keycloak_* / auth_mode args
    ):
        config = get_arkime_config()
        self.url = (url if url is not None else config.get("url", "")).rstrip("/")
        self.username = username if username is not None else config.get("username", "")
        self.password = password if password is not None else config.get("password", "")
        self.verify_ssl = verify_ssl if verify_ssl is not None else config.get("verify_ssl", True)

    @property
    def _has_basic(self) -> bool:
        return bool(self.username and self.password)

    @property
    def is_configured(self) -> bool:
        """Basic auth only — username + password are mandatory."""
        return bool(self.url and self._has_basic)

    async def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Build request headers with HTTP Basic auth.

        Single auth path — no httpx auth objects, no digest challenge, no
        API-key scheme. If ``ION_ARKIME_USERNAME``/``_PASSWORD`` aren't
        set, ``is_configured`` returns False and callers short-circuit
        before we ever get here.
        """
        headers: Dict[str, str] = {"Accept": "application/json"}
        if self._has_basic:
            import base64
            creds = base64.b64encode(
                f"{self.username}:{self.password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {creds}"
        if extra:
            headers.update(extra)
        return headers

    async def _client(self) -> httpx.AsyncClient:
        """Client for session-search / user-probe calls. Short timeout (60s)."""
        return httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=60.0,
            follow_redirects=True,
        )

    async def _pcap_client(self) -> httpx.AsyncClient:
        """Longer-timeout client for PCAP downloads.

        Arkime assembles PCAPs server-side by walking capture files — a busy
        session can easily need 30-120s to produce, plus transfer time. The
        60s session-search timeout was cutting PCAP downloads off mid-flight
        and surfacing blank-message ``ArkimeError: Arkime PCAP download
        error:`` to operators. Default 300s, tunable via
        ``ION_ARKIME_PCAP_TIMEOUT_S`` for very large sessions.
        """
        return httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=_env_float("ION_ARKIME_PCAP_TIMEOUT_S", 300.0),
            follow_redirects=True,
        )

    # ── Probes ─────────────────────────────────────────────────────────────
    async def test_connection(self) -> Dict[str, Any]:
        """Verify we can talk to Arkime. Returns status dict for the UI."""
        if not self.is_configured:
            return {"connected": False, "error": "Arkime is not configured"}
        headers = await self._headers()
        try:
            async with await self._client() as client:
                resp = await client.get(
                    f"{self.url}/api/user",
                    headers=headers,
                )
            if resp.status_code == 200:
                data: Dict[str, Any] = {}
                try:
                    data = resp.json()
                except ValueError:
                    pass
                return {
                    "connected": True,
                    "url": self.url,
                    "user": data.get("userId") or self.username or "",
                    "auth_mode": "basic",
                }
            return {
                "connected": False,
                "url": self.url,
                "error": f"HTTP {resp.status_code}",
            }
        except httpx.HTTPError as e:
            return {"connected": False, "url": self.url, "error": str(e)}

    # ── Session lookup ─────────────────────────────────────────────────────
    _SESSION_FIELDS = (
        "id,node,firstPacket,lastPacket,srcIp,dstIp,srcPort,dstPort,"
        "ipProtocol,protocol,packets,bytes,communityId"
    )

    async def find_sessions_by_community_id(
        self,
        node: str,
        community_id: str,
        *,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Search Arkime for sessions matching a Community ID flow hash.

        Returns a list of session documents (possibly empty). The PCAP
        download endpoint needs the `id` field from one of these docs.

        Note: ``community_id`` is a globally-unique flow hash by design
        (identical across all capture nodes observing the same flow), so
        we do NOT filter by node here — an alert's ``arkime_node`` value
        often doesn't exactly match the node string stored on the session
        (hostname vs FQDN, case differences). The caller disambiguates
        between multi-node matches when downloading the PCAP.
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        expression = f'communityId == "{community_id}"'
        params = {
            "expression": expression,
            "length": str(limit),
            "fields": self._SESSION_FIELDS,
        }
        logger.info(
            "Arkime community_id search: expression=%r (alert node hint=%r)",
            expression, node,
        )
        headers = await self._headers()
        try:
            async with await self._client() as client:
                resp = await client.get(
                    f"{self.url}/api/sessions",
                    headers=headers,
                    params=params,
                )
            if resp.status_code != 200:
                body_preview = (resp.text or "")[:200]
                logger.warning(
                    "Arkime session search HTTP %d: %s", resp.status_code, body_preview,
                )
                raise ArkimeError(
                    f"Arkime session search failed: HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            # Guard against non-JSON responses (e.g. HTML login redirect)
            content_type = resp.headers.get("content-type", "")
            if "json" not in content_type:
                body_preview = (resp.text or "")[:200]
                logger.warning(
                    "Arkime returned non-JSON (%s): %s", content_type, body_preview,
                )
                raise ArkimeError(
                    f"Arkime returned non-JSON response ({content_type}). "
                    f"Check auth — this usually means a login redirect.",
                )
            try:
                payload = resp.json()
            except Exception:
                raise ArkimeError(
                    f"Arkime response is not valid JSON: {(resp.text or '')[:100]}"
                )
            data = payload.get("data") if isinstance(payload, dict) else None
            if isinstance(data, list):
                return data
            return []
        except ArkimeError:
            raise
        except httpx.HTTPError as e:
            raise ArkimeError(
                f"Arkime session search error: {type(e).__name__}: {e}"
            ) from e

    async def find_sessions_by_ip(
        self,
        node: str,
        ip: str,
        *,
        alert_timestamp: Any = None,
        window_minutes: Optional[int] = None,
        hours: Optional[int] = None,  # deprecated: kept for call-site compat
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Search Arkime for sessions involving an IP within a time window.

        Fallback when community_id doesn't resolve a session. Searches both
        source and destination. When *node* is empty the node filter is
        omitted.

        v0.10.13: the search window now anchors on ``alert_timestamp`` when
        provided (``± window_minutes``) rather than on wall-clock ``now``.
        Non-24/7 SOCs frequently investigate alerts hours after they fired;
        a now-anchored window would miss the traffic entirely in that case.
        Falls back to a now-anchored window only when no alert timestamp
        is supplied.

        ``window_minutes`` defaults to ``ION_ARKIME_IP_SEARCH_WINDOW_MIN``
        (default 30). The legacy ``hours`` kwarg is still honoured — older
        callers don't need to change. Mixing both: ``window_minutes`` wins.
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        expression = f'(ip.src == {ip} || ip.dst == {ip})'
        if node:
            expression += f' && node == "{node}"'

        # Resolve effective window. Precedence: explicit window_minutes →
        # legacy hours (×60) → env default → 30min.
        if window_minutes is None:
            if hours is not None:
                window_minutes = hours * 60
            else:
                window_minutes = _env_int("ION_ARKIME_IP_SEARCH_WINDOW_MIN", 30)

        alert_epoch = _parse_alert_epoch(alert_timestamp)
        window_s = window_minutes * 60
        if alert_epoch is not None:
            start_ts = alert_epoch - window_s
            stop_ts = alert_epoch + window_s
            anchor = f"alert_ts={alert_epoch}"
        else:
            start_ts = int(time.time() - window_s)
            stop_ts = int(time.time())
            anchor = "now"

        params = {
            "expression": expression,
            "length": str(limit),
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
            "fields": self._SESSION_FIELDS,
        }
        logger.info(
            "Arkime IP search: expression=%r window=±%dmin anchor=%s limit=%d",
            expression, window_minutes, anchor, limit,
        )
        headers = await self._headers()
        try:
            async with await self._client() as client:
                resp = await client.get(
                    f"{self.url}/api/sessions",
                    headers=headers,
                    params=params,
                )
            if resp.status_code != 200:
                body_preview = (resp.text or "")[:200]
                logger.warning(
                    "Arkime IP session search HTTP %d: %s", resp.status_code, body_preview,
                )
                raise ArkimeError(
                    f"Arkime IP session search failed: HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            content_type = resp.headers.get("content-type", "")
            if "json" not in content_type:
                body_preview = (resp.text or "")[:200]
                logger.warning(
                    "Arkime IP search returned non-JSON (%s): %s", content_type, body_preview,
                )
                raise ArkimeError(
                    f"Arkime returned non-JSON response ({content_type}). Check auth config.",
                )
            try:
                payload = resp.json()
            except Exception:
                raise ArkimeError(
                    f"Arkime response is not valid JSON: {(resp.text or '')[:100]}"
                )
            data = payload.get("data") if isinstance(payload, dict) else None
            return data if isinstance(data, list) else []
        except ArkimeError:
            raise
        except httpx.HTTPError as e:
            raise ArkimeError(
                f"Arkime IP session search error: {type(e).__name__}: {e}"
            ) from e

    # ── PCAP download ──────────────────────────────────────────────────────
    async def download_pcap_by_community_id(
        self,
        node: str,
        community_id: str,
    ) -> Dict[str, Any]:
        """Resolve a Community ID to an Arkime session and fetch the PCAP.

        Returns:
            {
                "pcap": bytes,           # raw PCAP body
                "session": dict,         # the resolved Arkime session document
                "other_matches": list,   # additional sessions matching this
                                         # Community ID (not downloaded)
            }
        """
        sessions = await self.find_sessions_by_community_id(node, community_id)
        if not sessions:
            raise ArkimeError(
                f"No Arkime sessions matched community_id={community_id}",
                status_code=404,
            )
        # Prefer a session whose node matches the alert hint, falling back to
        # the first result when no exact match (Arkime's node string often
        # doesn't equal the alert's arkime_node — FQDN/case differences).
        primary: Dict[str, Any] = sessions[0]
        if node:
            for s in sessions:
                if (s.get("node") or "").strip() == node.strip():
                    primary = s
                    break
        arkime_session_id = primary.get("id") or primary.get("_id")
        if not arkime_session_id:
            raise ArkimeError("Arkime session document missing `id` field")
        # Resolve node from the chosen session itself — the alert's node hint
        # may differ in case or FQDN from what Arkime stores.
        resolved_node = primary.get("node") or node or ""
        if not resolved_node:
            raise ArkimeError("Cannot determine Arkime node for PCAP download")
        pcap_bytes = await self.download_pcap(resolved_node, str(arkime_session_id))
        other_matches = [s for s in sessions if s is not primary]
        return {
            "pcap": pcap_bytes,
            "session": primary,
            "other_matches": other_matches,
        }

    # ── Traffic analytics ──────────────────────────────────────────────────

    _COUNTRY_SAMPLE = 500  # sessions fetched for geo / node aggregation
    _TALKER_SAMPLE  = 500  # sessions fetched when filtering private IPs

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """True for RFC-1918 addresses (10/8, 172.16/12, 192.168/16).

        Intentionally narrow: only filter routable internal networks, not
        documentation / test ranges (203.0.113.0/24 etc.) that show up in
        real pcap but are not east-west internal traffic.
        """
        import ipaddress
        _RFC1918 = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in _RFC1918)
        except ValueError:
            return False

    async def get_traffic_overview(
        self,
        start_ts: int,
        stop_ts: int,
    ) -> Dict[str, Any]:
        """Fetch aggregated traffic histogram + protocol mix from Arkime.

        Calls /api/sessions?facets=1&length=0 so Arkime returns only the
        graph aggregations (srcDataHisto, dstDataHisto, protocols) with no
        actual session rows in the payload — analogous to ES size=0 queries.

        Returns:
            {
                "src_histo":  [[epoch_ms, bytes], ...],
                "dst_histo":  [[epoch_ms, bytes], ...],
                "protocols":  {"tcp": N, "udp": N, ...},
                "total_sessions": N,
                "total_bytes": N,
            }
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        params = {
            "facets": "1",
            "length": "0",
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
        }
        headers = await self._headers()
        try:
            async with await self._client() as client:
                resp = await client.get(
                    f"{self.url}/api/sessions",
                    headers=headers,
                    params=params,
                )
            if resp.status_code != 200:
                raise ArkimeError(
                    f"Arkime traffic overview failed: HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            content_type = resp.headers.get("content-type", "")
            if "json" not in content_type:
                raise ArkimeError(
                    f"Arkime returned non-JSON ({content_type}) — check auth"
                )
            payload = resp.json()
            graph = payload.get("graph") or {}
            return {
                "src_histo": graph.get("srcDataHisto") or [],
                "dst_histo": graph.get("dstDataHisto") or [],
                "protocols": graph.get("protocols") or {},
                "total_sessions": payload.get("recordsFiltered") or payload.get("total") or 0,
                "total_bytes": graph.get("totDataBytes") or 0,
            }
        except ArkimeError:
            raise
        except httpx.HTTPError as e:
            raise ArkimeError(f"Arkime traffic overview error: {type(e).__name__}: {e}") from e

    async def get_top_talkers(
        self,
        start_ts: int,
        stop_ts: int,
        limit: int = 10,
        exclude_private_to_private: bool = True,
    ) -> Dict[str, Any]:
        """Fetch top sessions by total bytes for the given time window.

        When exclude_private_to_private=True (default), sessions where both
        source and destination are RFC-1918 addresses are dropped before ranking
        — this removes internal east-west chatter that floods the top-talker
        list and obscures external flows of interest.

        Returns:
            {
                "by_src": [{"ip": "1.2.3.4", "bytes": N, "sessions": N}, ...],
                "by_dst": [{"ip": "1.2.3.4", "bytes": N, "sessions": N}, ...],
            }
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        fetch_len = self._TALKER_SAMPLE if exclude_private_to_private else limit
        params = {
            "length": str(fetch_len),
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
            "order": "totBytes:desc",
            "fields": "srcIp,dstIp,totBytes,packets",
        }
        headers = await self._headers()
        try:
            async with await self._client() as client:
                resp = await client.get(
                    f"{self.url}/api/sessions",
                    headers=headers,
                    params=params,
                )
            if resp.status_code != 200:
                raise ArkimeError(
                    f"Arkime top-talkers failed: HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            content_type = resp.headers.get("content-type", "")
            if "json" not in content_type:
                raise ArkimeError(
                    f"Arkime returned non-JSON ({content_type}) — check auth"
                )
            payload = resp.json()
            sessions = payload.get("data") or []

            # Aggregate bytes + session count per src/dst IP
            src_map: Dict[str, Dict[str, int]] = {}
            dst_map: Dict[str, Dict[str, int]] = {}
            for s in sessions:
                src = s.get("srcIp") or s.get("source", {}).get("ip", "")
                dst = s.get("dstIp") or s.get("destination", {}).get("ip", "")
                b = int(s.get("totBytes") or 0)
                if exclude_private_to_private and src and dst:
                    if self._is_private_ip(src) and self._is_private_ip(dst):
                        continue
                if src:
                    entry = src_map.setdefault(src, {"bytes": 0, "sessions": 0})
                    entry["bytes"] += b
                    entry["sessions"] += 1
                if dst:
                    entry = dst_map.setdefault(dst, {"bytes": 0, "sessions": 0})
                    entry["bytes"] += b
                    entry["sessions"] += 1

            def _rank(m: Dict[str, Dict[str, int]]) -> List[Dict[str, Any]]:
                return sorted(
                    [{"ip": ip, **stats} for ip, stats in m.items()],
                    key=lambda x: x["bytes"],
                    reverse=True,
                )[:limit]

            return {"by_src": _rank(src_map), "by_dst": _rank(dst_map)}
        except ArkimeError:
            raise
        except httpx.HTTPError as e:
            raise ArkimeError(f"Arkime top-talkers error: {type(e).__name__}: {e}") from e

    async def get_top_countries(
        self,
        start_ts: int,
        stop_ts: int,
        limit: int = 15,
    ) -> Dict[str, Any]:
        """Fetch top countries by traffic volume for the given time window.

        Aggregates srcGEO/dstGEO (Arkime MaxMind ISO 3166-1 alpha-2 codes)
        across the top _COUNTRY_SAMPLE sessions by bytes. Bias towards heavy
        sessions is intentional — country totals are dominated by high-byte flows.

        Returns:
            {
                "by_src": [{"country": "US", "bytes": N, "sessions": N}, ...],
                "by_dst": [{"country": "US", "bytes": N, "sessions": N}, ...],
            }
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        params = {
            "length": str(self._COUNTRY_SAMPLE),
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
            "order": "totBytes:desc",
            "fields": "srcGEO,dstGEO,totBytes",
        }
        headers = await self._headers()
        try:
            async with await self._client() as client:
                resp = await client.get(
                    f"{self.url}/api/sessions",
                    headers=headers,
                    params=params,
                )
            if resp.status_code != 200:
                raise ArkimeError(
                    f"Arkime top-countries failed: HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            content_type = resp.headers.get("content-type", "")
            if "json" not in content_type:
                raise ArkimeError(
                    f"Arkime returned non-JSON ({content_type}) — check auth"
                )
            payload = resp.json()
            sessions = payload.get("data") or []

            src_map: Dict[str, Dict[str, int]] = {}
            dst_map: Dict[str, Dict[str, int]] = {}
            for s in sessions:
                src_geo = (s.get("srcGEO") or "").strip().upper()
                dst_geo = (s.get("dstGEO") or "").strip().upper()
                b = int(s.get("totBytes") or 0)
                if src_geo:
                    entry = src_map.setdefault(src_geo, {"bytes": 0, "sessions": 0})
                    entry["bytes"] += b
                    entry["sessions"] += 1
                if dst_geo:
                    entry = dst_map.setdefault(dst_geo, {"bytes": 0, "sessions": 0})
                    entry["bytes"] += b
                    entry["sessions"] += 1

            def _rank(m: Dict[str, Dict[str, int]]) -> List[Dict[str, Any]]:
                return sorted(
                    [{"country": cc, **stats} for cc, stats in m.items()],
                    key=lambda x: x["bytes"],
                    reverse=True,
                )[:limit]

            return {"by_src": _rank(src_map), "by_dst": _rank(dst_map)}
        except ArkimeError:
            raise
        except httpx.HTTPError as e:
            raise ArkimeError(f"Arkime top-countries error: {type(e).__name__}: {e}") from e

    async def get_per_node_traffic(
        self,
        start_ts: int,
        stop_ts: int,
    ) -> Dict[str, Any]:
        """Aggregate traffic volume per Arkime capture node for the time window.

        Returns:
            {
                "nodes": [{"node": "dc-core-01", "bytes": N, "sessions": N}, ...]
            }
            Sorted descending by bytes.
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        params = {
            "length": str(self._COUNTRY_SAMPLE),
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
            "order": "totBytes:desc",
            "fields": "node,totBytes",
        }
        headers = await self._headers()
        try:
            async with await self._client() as client:
                resp = await client.get(
                    f"{self.url}/api/sessions",
                    headers=headers,
                    params=params,
                )
            if resp.status_code != 200:
                raise ArkimeError(
                    f"Arkime per-node failed: HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            content_type = resp.headers.get("content-type", "")
            if "json" not in content_type:
                raise ArkimeError(
                    f"Arkime returned non-JSON ({content_type}) — check auth"
                )
            payload = resp.json()
            sessions = payload.get("data") or []

            node_map: Dict[str, Dict[str, int]] = {}
            for s in sessions:
                node = (s.get("node") or "unknown").strip()
                b = int(s.get("totBytes") or 0)
                entry = node_map.setdefault(node, {"bytes": 0, "sessions": 0})
                entry["bytes"] += b
                entry["sessions"] += 1

            nodes = sorted(
                [{"node": n, **stats} for n, stats in node_map.items()],
                key=lambda x: x["bytes"],
                reverse=True,
            )
            return {"nodes": nodes}
        except ArkimeError:
            raise
        except httpx.HTTPError as e:
            raise ArkimeError(f"Arkime per-node error: {type(e).__name__}: {e}") from e

    async def download_pcap(self, node: str, session_id: str) -> bytes:
        """Download the raw PCAP bytes for a single Arkime session.

        Arkime 5.x URL pattern:
            {base}/api/session/{node}/3@{sessionId}/pcap

        The ``3@`` prefix is required by Arkime's session routing — it
        tells the viewer which DB version the session belongs to.
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        if not node or not session_id:
            raise ArkimeError("Both `node` and `session_id` are required")

        # Ensure 3@ prefix (don't double-add if already present)
        if not session_id.startswith("3@"):
            session_id = f"3@{session_id}"

        url = f"{self.url}/api/session/{node}/{session_id}/pcap"
        headers = await self._headers({"Accept": "application/vnd.tcpdump.pcap"})
        logger.info("Arkime PCAP GET %s", url)
        try:
            async with await self._pcap_client() as client:
                resp = await client.get(
                    url,
                    headers=headers,
                )
            if resp.status_code == 404:
                raise ArkimeError(
                    f"Arkime session {session_id} not found on node {node}",
                    status_code=404,
                )
            if resp.status_code != 200:
                raise ArkimeError(
                    f"Arkime PCAP download failed: HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            body = resp.content
            if not body:
                raise ArkimeError("Arkime returned an empty PCAP body")
            return body
        except httpx.HTTPError as e:
            # Include the exception class name — httpx.ReadTimeout/ConnectTimeout
            # have empty str() representations and surfacing just "Arkime PCAP
            # download error:" told operators nothing. With the class name,
            # timeouts vs connection refusals vs TLS errors are immediately
            # distinguishable.
            raise ArkimeError(
                f"Arkime PCAP download error: {type(e).__name__}: {e}"
            ) from e


# Singleton
_arkime_service: Optional[ArkimeService] = None


def get_arkime_service() -> ArkimeService:
    global _arkime_service
    if _arkime_service is None:
        _arkime_service = ArkimeService()
    return _arkime_service


def reset_arkime_service() -> None:
    global _arkime_service
    _arkime_service = None
