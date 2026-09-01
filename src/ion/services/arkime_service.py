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

import ipaddress
import logging
import os
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote

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


def escape_arkime_quoted(value: Any) -> str:
    """Escape a value for interpolation inside a double-quoted Arkime
    expression term. communityIds and node names originate from ES documents
    and (worse) from case-note content — a quote must not break out of the
    term. Same escaping the horizon query applies to node names."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


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
    # Indexed depth fields (Arkime 5.x): TLS fingerprints + HTTP metadata the
    # viewer already parsed — reading them is free vs re-deriving from PCAP.
    # Requested separately because some builds 400 the WHOLE query when an
    # unknown name appears in fields= (same trap as country.* in fields=);
    # _fields_param degrades to the base list once a 400 is seen.
    _DEPTH_FIELDS = "tls.ja3,tls.ja4,http.uri,http.useragent"

    # None = untested, True = extended fields accepted, False = a 400 was seen
    # and all further requests stick to base fields for this service instance.
    _depth_fields_ok: Optional[bool] = None

    def _fields_param(self, base: str) -> str:
        """Base field list plus the depth fields, unless a prior 400 proved
        this Arkime build rejects them."""
        if self._depth_fields_ok is False:
            return base
        return f"{base},{self._DEPTH_FIELDS}"

    def _note_fields_rejected(self, status_code: int, params: Dict[str, str], base: str) -> bool:
        """After a 400 on a request that carried depth fields, latch the
        degrade and tell the caller to retry with base fields."""
        if (
            status_code == 400
            and self._depth_fields_ok is not False
            and params.get("fields", "") != base
        ):
            self._depth_fields_ok = False
            logger.info(
                "Arkime rejected extended SPI fields (HTTP 400) — degrading to base field list"
            )
            return True
        return False

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
        expression = f'communityId == "{escape_arkime_quoted(community_id)}"'
        params = {
            "expression": expression,
            "length": str(limit),
            "fields": self._fields_param(self._SESSION_FIELDS),
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
                if self._note_fields_rejected(resp.status_code, params, self._SESSION_FIELDS):
                    params["fields"] = self._SESSION_FIELDS
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
        # `ip` originates from adversary-influenceable alert fields
        # (source_ip / destination_ip), so validate it as a real address before
        # interpolating into the Arkime expression — otherwise a crafted value
        # breaks out of the term (node is escaped below; ip must be validated).
        try:
            ip = str(ipaddress.ip_address(str(ip).strip()))
        except ValueError as e:
            raise ArkimeError(f"Invalid IP for Arkime search: {ip!r}") from e
        expression = f'(ip.src == {ip} || ip.dst == {ip})'
        if node:
            # node originates from an ES alert document; escape quote/backslash
            # so a crafted value can't break out of the quoted Arkime term.
            safe_node = str(node).replace("\\", "\\\\").replace('"', '\\"')
            expression += f' && node == "{safe_node}"'

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
            "fields": self._fields_param(self._SESSION_FIELDS),
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
                if self._note_fields_rejected(resp.status_code, params, self._SESSION_FIELDS):
                    params["fields"] = self._SESSION_FIELDS
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
    _PROTO_SAMPLE   = 1000  # sessions fetched for protocol-mix fallback
    _IPPROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "ipv6-icmp"}

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

    @staticmethod
    def _is_noise_ip(ip: str) -> bool:
        """True for addresses that are pure telemetry noise, not real talkers.

        Covers IPv6 link-local (fe80::/10), loopback (::1 / 127.0.0.0/8),
        the unspecified address (:: / 0.0.0.0), and IPv4 link-local
        (169.254.0.0/16 — is_link_local covers both families). These flood the
        top-talker aggregation with endpoints that carry no analytic value.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return addr.is_link_local or addr.is_loopback or addr.is_unspecified  # fe80::/10, ::1, ::, 169.254/16

    @staticmethod
    def build_exclusion_expression(cidrs: List[str]) -> str:
        """Arkime expression dropping any session that touches an excluded IP/CIDR.

        ``ip != X`` matches sessions where neither src nor dst is X, so ANDing
        the terms removes all traffic involving the excluded ranges. Invalid
        entries are skipped; returns '' when nothing valid is supplied (callers
        then pass no expression). Combine with a caller expression via ``&&``.
        """
        import ipaddress
        terms: List[str] = []
        for raw in cidrs or []:
            c = (raw or "").strip()
            if not c:
                continue
            try:
                ipaddress.ip_network(c, strict=False)
            except ValueError:
                continue
            terms.append(f"ip != {c}")
        return "(" + " && ".join(terms) + ")" if terms else ""

    @staticmethod
    def _geo_code(session: Dict[str, Any], side: str) -> str:
        """ISO country code for a session side ('src' | 'dst').

        Arkime exposes the GeoIP country under several shapes depending on the
        viewer version / field config: the flat db field ``srcGEO``/``dstGEO``,
        the expression-style flat key ``country.src``/``country.dst``, or a
        nested ``{"country": {"src": ...}}`` object. Some builds return a list
        when a session spans multiple geos. Be tolerant of every shape — the
        prior code only read ``srcGEO``/``dstGEO`` and silently produced an
        empty map on deployments that return ``country.src``/``country.dst``.
        """
        candidates = [session.get(f"{side}GEO"), session.get(f"country.{side}")]
        country_obj = session.get("country")
        if isinstance(country_obj, dict):
            candidates.append(country_obj.get(side))
        for c in candidates:
            if isinstance(c, (list, tuple)):
                c = c[0] if c else None
            if c:
                return str(c).strip().upper()
        return ""

    async def get_traffic_overview(
        self,
        start_ts: int,
        stop_ts: int,
        expression: Optional[str] = None,
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
        if expression:
            params["expression"] = expression
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
            # Protocol mix: the facets `graph.protocols` key is absent on many
            # Arkime builds (it moved / was never populated for this deployment),
            # which left the doughnut empty. Next-best is a server-side spigraph
            # bucket aggregation (whole window, unbiased); the session-sample
            # count is the last resort.
            protocols = graph.get("protocols") or graph.get("protocolCnt") or {}
            protocols_method = "facets"
            if not protocols:
                try:
                    buckets = await self._spigraph_buckets(
                        "protocols", start_ts, stop_ts, expression
                    )
                    protocols = {
                        str(name).strip().lower(): stats["sessions"]
                        for name, stats in buckets.items()
                        if str(name).strip() and stats.get("sessions")
                    }
                    protocols_method = "spigraph"
                except (ArkimeError, httpx.HTTPError) as exc:
                    logger.debug(
                        "Arkime spigraph protocol aggregation failed (%s) — falling back to sampling",
                        exc,
                    )
                    protocols = {}
            if not protocols:
                protocols = await self._sample_protocol_mix(start_ts, stop_ts, expression)
                protocols_method = "sample"

            def _first(d, *keys):
                for k in keys:
                    v = d.get(k)
                    if v:
                        return v
                return None

            # The facet-graph series were renamed between Moloch/OpenArkime
            # 2–3.x (srcDataHisto/dstDataHisto/totDataBytes) and Arkime 4.x/5.x
            # (source.bytesHisto/destination.bytesHisto, per-side byte totals).
            # Try the legacy names first (keeps the mocked tests green) then the
            # newer ones, so the volume chart populates on either dialect.
            total_bytes = (
                graph.get("totDataBytes")
                or (graph.get("source.bytes") or 0) + (graph.get("destination.bytes") or 0)
                or payload.get("totalBytes")
                or 0
            )
            return {
                "src_histo": _first(graph, "srcDataHisto", "source.bytesHisto", "srcBytesHisto") or [],
                "dst_histo": _first(graph, "dstDataHisto", "destination.bytesHisto", "dstBytesHisto") or [],
                "protocols": protocols,
                "protocols_method": protocols_method,
                "total_sessions": (
                    payload.get("recordsFiltered")
                    or payload.get("recordsTotal")
                    or payload.get("total")
                    or 0
                ),
                "total_bytes": total_bytes,
            }
        except ArkimeError:
            raise
        except httpx.HTTPError as e:
            raise ArkimeError(f"Arkime traffic overview error: {type(e).__name__}: {e}") from e

    # Default SPI fields pulled for realtime-monitor candidate sweeps. Includes
    # Arkime's aggregate ``user`` field (a cleartext username parsed from any
    # auth-bearing protocol) and ``dns.host`` (queried names) so the content/
    # behaviour detectors can score candidates without pulling PCAP.
    _RTMON_FIELDS = (
        "id,node,communityId,srcIp,dstIp,srcPort,dstPort,totBytes,packets,"
        "firstPacket,lastPacket,ipProtocol,protocol,user,dns.host"
    )

    async def find_recent_sessions_by_expression(
        self,
        expression: str,
        *,
        window_minutes: int = 20,
        limit: int = 500,
        fields: Optional[str] = None,
        order: str = "firstPacket:desc",
    ) -> List[Dict[str, Any]]:
        """Sessions in the last ``window_minutes`` matching an Arkime expression.

        The generic primitive behind the realtime monitor's content/behaviour
        detectors: each detector supplies its own Arkime search expression
        (cleartext-auth protocols, suspicious egress ports, DNS, …) and reads
        back SPI metadata only — no PCAP cost. Callers do their own per-detector
        scoring/grouping in Python. Returns ``[]`` (never raises) on an empty
        expression so a disabled detector is a no-op.
        """
        import time as _time

        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        expr = (expression or "").strip()
        if not expr:
            return []
        now = int(_time.time())
        start = now - max(1, window_minutes) * 60
        base_fields = fields or self._RTMON_FIELDS
        params = {
            "length": str(max(1, min(limit, 1000))),
            "startTime": str(start),
            "stopTime": str(now),
            "order": order,
            "expression": expr,
            "fields": base_fields if fields else self._fields_param(self._RTMON_FIELDS),
        }
        headers = await self._headers()
        try:
            async with await self._client() as client:
                resp = await client.get(
                    f"{self.url}/api/sessions", headers=headers, params=params
                )
                if self._note_fields_rejected(resp.status_code, params, base_fields):
                    params["fields"] = base_fields
                    resp = await client.get(
                        f"{self.url}/api/sessions", headers=headers, params=params
                    )
            if resp.status_code != 200:
                raise ArkimeError(
                    f"Arkime realtime-monitor query failed: HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            if "json" not in resp.headers.get("content-type", ""):
                raise ArkimeError("Arkime returned non-JSON — check auth")
            return resp.json().get("data") or []
        except ArkimeError:
            raise
        except httpx.HTTPError as e:
            raise ArkimeError(f"Arkime realtime-monitor error: {type(e).__name__}: {e}") from e

    async def find_recent_sessions_for_ips(
        self,
        ips: List[str],
        *,
        window_minutes: int = 20,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        """Sessions in the last ``window_minutes`` that touch any IP in ``ips``
        (as src OR dst). Used by the realtime monitor's legacy IOC-IP detector
        (opt-in) to catch known-bad traffic while the full PCAP is still inside
        Arkime's retention window.

        Caps the IP set to keep the Arkime expression bounded; delegates the
        HTTP call to :meth:`find_recent_sessions_by_expression`.
        """
        clean = [str(i).strip() for i in (ips or []) if str(i).strip()][:256]
        if not clean:
            return []
        return await self.find_recent_sessions_by_expression(
            "ip == [" + ",".join(clean) + "]",
            window_minutes=window_minutes,
            limit=limit,
        )

    async def get_traffic_totals(
        self, start_ts: int, stop_ts: int, expression: Optional[str] = None
    ) -> Dict[str, int]:
        """Just the session + byte totals for a window (facets, no rows) — used
        for cheap period-over-period trend deltas without the full overview."""
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        params = {
            "facets": "1", "length": "0",
            "startTime": str(start_ts), "stopTime": str(stop_ts),
        }
        if expression:
            params["expression"] = expression
        headers = await self._headers()
        try:
            async with await self._client() as client:
                resp = await client.get(
                    f"{self.url}/api/sessions", headers=headers, params=params
                )
            if resp.status_code != 200 or "json" not in resp.headers.get("content-type", ""):
                return {"total_sessions": 0, "total_bytes": 0}
            payload = resp.json()
            graph = payload.get("graph") or {}
            return {
                "total_sessions": payload.get("recordsFiltered") or payload.get("total") or 0,
                "total_bytes": graph.get("totDataBytes") or 0,
            }
        except httpx.HTTPError:
            return {"total_sessions": 0, "total_bytes": 0}

    async def get_node_traffic_profile(
        self, node: str, start_ts: int, stop_ts: int, expression: Optional[str] = None
    ) -> Dict[str, Any]:
        """Assemble a compact traffic profile for one capture node + window —
        the context block the AI traffic-pattern review reasons over. Combines
        the node filter with any caller expression (e.g. exclusions)."""
        node_expr = f'node == "{node}"'
        expr = f"({node_expr}) && {expression}" if expression else node_expr
        overview = await self.get_traffic_overview(start_ts, stop_ts, expression=expr)
        talkers = await self.get_top_talkers(
            start_ts, stop_ts, limit=10, exclude_private_to_private=True, expression=expr
        )
        countries = await self.get_top_countries(start_ts, stop_ts, limit=10, expression=expr)
        return {
            "node": node,
            "total_sessions": overview.get("total_sessions", 0),
            "total_bytes": overview.get("total_bytes", 0),
            "protocols": overview.get("protocols", {}),
            "top_src": talkers.get("by_src", [])[:10],
            "top_dst": talkers.get("by_dst", [])[:10],
            "src_countries": countries.get("by_src", [])[:10],
            "dst_countries": countries.get("by_dst", [])[:10],
        }

    async def _sample_protocol_mix(
        self, start_ts: int, stop_ts: int, expression: Optional[str] = None
    ) -> Dict[str, int]:
        """Protocol-count map from a session sample — fallback when the facets
        graph carries no protocol breakdown. Counts Arkime ``protocol`` tags
        (app-layer: http/tls/dns/…), falling back to the L4 ``ipProtocol``."""
        params = {
            "length": str(self._PROTO_SAMPLE),
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
            "order": "totBytes:desc",
            "fields": "protocol,ipProtocol",
        }
        if expression:
            params["expression"] = expression
        headers = await self._headers()
        out: Dict[str, int] = {}
        try:
            async with await self._client() as client:
                resp = await client.get(
                    f"{self.url}/api/sessions", headers=headers, params=params
                )
            if resp.status_code != 200 or "json" not in resp.headers.get("content-type", ""):
                return out
            for s in (resp.json().get("data") or []):
                protos = s.get("protocol")
                if isinstance(protos, str):
                    protos = [protos]
                if not protos:
                    ipp = s.get("ipProtocol")
                    name = (
                        self._IPPROTO_NAMES.get(ipp) if isinstance(ipp, int)
                        else (str(ipp).lower() if ipp else None)
                    )
                    protos = [name] if name else []
                for p in protos:
                    p = str(p).strip().lower()
                    if p:
                        out[p] = out.get(p, 0) + 1
        except httpx.HTTPError:
            return out
        return out

    # Expression-side twin of _is_private_ip — keep the two range lists in sync
    # or the spigraph and sampled top-talker paths disagree on what "internal
    # east-west" means.
    _RFC1918_EXPR = "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"

    async def get_top_talkers(
        self,
        start_ts: int,
        stop_ts: int,
        limit: int = 10,
        exclude_private_to_private: bool = True,
        expression: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Top talkers by byte volume for the given time window.

        Primary path is server-side ``/api/spigraph`` bucket aggregation over
        every session in the window; falls back to the legacy top-N-by-bytes
        session sample when spigraph is unavailable. ``method`` in the result
        says which path produced the numbers ("spigraph" | "sample").

        When exclude_private_to_private=True (default), sessions where both
        source and destination are RFC-1918 addresses are dropped — this
        removes internal east-west chatter that floods the top-talker list and
        obscures external flows of interest. On the spigraph path the drop
        happens in the Arkime expression itself.

        Returns:
            {
                "by_src": [{"ip": "1.2.3.4", "bytes": N, "sessions": N}, ...],
                "by_dst": [{"ip": "1.2.3.4", "bytes": N, "sessions": N}, ...],
                "method": "spigraph" | "sample",
            }
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        expr = expression
        if exclude_private_to_private:
            no_pp = (
                f"!(ip.src == {self._RFC1918_EXPR} && ip.dst == {self._RFC1918_EXPR})"
            )
            expr = f"({expression}) && {no_pp}" if expression else no_pp
        try:
            src_buckets = await self._spigraph_buckets("ip.src", start_ts, stop_ts, expr)
            dst_buckets = await self._spigraph_buckets("ip.dst", start_ts, stop_ts, expr)
            if src_buckets or dst_buckets:
                def _rank_ips(m: Dict[str, Dict[str, int]]) -> List[Dict[str, Any]]:
                    # Secondary sort on sessions keeps the ranking meaningful on
                    # builds whose spigraph buckets omit byte sizes (all zero).
                    return sorted(
                        [
                            {"ip": ip, **stats}
                            for ip, stats in m.items()
                            if not self._is_noise_ip(ip)
                        ],
                        key=lambda x: (x["bytes"], x["sessions"]),
                        reverse=True,
                    )[:limit]
                return {
                    "by_src": _rank_ips(src_buckets),
                    "by_dst": _rank_ips(dst_buckets),
                    "method": "spigraph",
                }
            logger.debug("Arkime spigraph returned no talker buckets — falling back to sampling")
        except (ArkimeError, httpx.HTTPError) as exc:
            logger.debug("Arkime spigraph talker aggregation failed (%s) — falling back to sampling", exc)
        out = await self._top_talkers_sampled(
            start_ts, stop_ts, limit, exclude_private_to_private, expression
        )
        out["method"] = "sample"
        return out

    async def _top_talkers_sampled(
        self,
        start_ts: int,
        stop_ts: int,
        limit: int = 10,
        exclude_private_to_private: bool = True,
        expression: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Legacy fallback: aggregate the top _TALKER_SAMPLE sessions by bytes.
        Byte-biased and capped — spigraph is preferred; this keeps talkers
        flowing on builds without a usable /api/spigraph."""
        fetch_len = self._TALKER_SAMPLE if exclude_private_to_private else limit
        params = {
            "length": str(fetch_len),
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
            "order": "totBytes:desc",
            "fields": "srcIp,dstIp,totBytes,packets",
        }
        if expression:
            params["expression"] = expression
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
                # Drop IPv6 link-local / loopback / unspecified noise endpoints
                # so they don't pollute the ranking (fe80::/10, ::1, ::, 169.254/16).
                if src and not self._is_noise_ip(src):
                    entry = src_map.setdefault(src, {"bytes": 0, "sessions": 0})
                    entry["bytes"] += b
                    entry["sessions"] += 1
                if dst and not self._is_noise_ip(dst):
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

    @staticmethod
    def _rank_countries(m: Dict[str, Dict[str, int]], limit: int) -> List[Dict[str, Any]]:
        return sorted(
            [{"country": cc, **stats} for cc, stats in m.items()],
            key=lambda x: x["bytes"],
            reverse=True,
        )[:limit]

    async def get_top_countries(
        self,
        start_ts: int,
        stop_ts: int,
        limit: int = 15,
        expression: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch top countries by traffic volume for the given time window.

        Primary path is Arkime's server-side SPI-graph endpoint
        (``/api/spigraph?field=country.src|country.dst``). spigraph aggregation
        is done in the viewer over EVERY session in the window (not a
        top-_COUNTRY_SAMPLE-by-bytes sample), so the geo totals are unbiased and
        don't miss low-byte flows to interesting geographies.

        Falls back to the legacy srcGEO/dstGEO session-sampling method when
        spigraph is unavailable (older Arkime builds 404 /api/spigraph or reject
        the ``country.*`` field), so nothing regresses.

        Returns:
            {
                "by_src": [{"country": "US", "bytes": N, "sessions": N}, ...],
                "by_dst": [{"country": "US", "bytes": N, "sessions": N}, ...],
            }
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        try:
            src_map = await self._spigraph_countries("country.src", start_ts, stop_ts, expression)
            dst_map = await self._spigraph_countries("country.dst", start_ts, stop_ts, expression)
            if src_map or dst_map:
                return {
                    "by_src": self._rank_countries(src_map, limit),
                    "by_dst": self._rank_countries(dst_map, limit),
                    "method": "spigraph",
                }
            # Both empty — spigraph may not be populated on this build; try the
            # sampling method before concluding there's genuinely no geo data.
            logger.debug("Arkime spigraph returned no country buckets — falling back to sampling")
        except (ArkimeError, httpx.HTTPError) as exc:
            logger.debug("Arkime spigraph country aggregation failed (%s) — falling back to sampling", exc)
        out = await self._top_countries_sampled(start_ts, stop_ts, limit, expression)
        out["method"] = "sample"
        return out

    async def _spigraph_countries(
        self,
        field: str,
        start_ts: int,
        stop_ts: int,
        expression: Optional[str] = None,
    ) -> Dict[str, Dict[str, int]]:
        """Server-side country buckets for one side — ISO2-normalized keys."""
        buckets = await self._spigraph_buckets(field, start_ts, stop_ts, expression)
        out: Dict[str, Dict[str, int]] = {}
        for name, stats in buckets.items():
            cc = str(name).strip().upper()
            if not cc:
                continue
            entry = out.setdefault(cc, {"bytes": 0, "sessions": 0})
            entry["bytes"] += stats.get("bytes", 0)
            entry["sessions"] += stats.get("sessions", 0)
        return out

    async def _spigraph_buckets(
        self,
        field: str,
        start_ts: int,
        stop_ts: int,
        expression: Optional[str] = None,
        length: int = 100,
    ) -> Dict[str, Dict[str, int]]:
        """Server-side value buckets for any field via ``/api/spigraph``.

        Aggregation runs in the viewer over EVERY session in the window — no
        sample bias. Returns ``{value: {"bytes": N, "sessions": N}}``. Raises
        ``ArkimeError`` on a non-200 or non-JSON response so callers can fall
        back to session sampling. spigraph buckets carry ``name`` (the field
        value), ``count`` (session count), and ``size`` (summed byte volume on
        builds that report it); we read every shape defensively and skip
        anything unparseable.
        """
        params = {
            "field": field,
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
            "length": str(length),
        }
        if expression:
            params["expression"] = expression
        headers = await self._headers()
        async with await self._client() as client:
            resp = await client.get(
                f"{self.url}/api/spigraph",
                headers=headers,
                params=params,
            )
        if resp.status_code != 200:
            raise ArkimeError(
                f"Arkime spigraph failed: HTTP {resp.status_code}",
                status_code=resp.status_code,
            )
        content_type = resp.headers.get("content-type", "")
        if "json" not in content_type:
            raise ArkimeError(f"Arkime returned non-JSON ({content_type}) — check auth")
        payload = resp.json()
        out: Dict[str, Dict[str, int]] = {}
        for item in payload.get("items") or []:
            name = item.get("name")
            if isinstance(name, (list, tuple)):
                name = name[0] if name else None
            key = str(name).strip() if name is not None else ""
            if not key:
                continue
            graph = item.get("graph") if isinstance(item.get("graph"), dict) else {}
            try:
                b = int(item.get("size") or graph.get("totDataBytes") or graph.get("totBytes") or 0)
            except (TypeError, ValueError):
                b = 0
            try:
                sess = int(item.get("count") or 0)
            except (TypeError, ValueError):
                sess = 0
            entry = out.setdefault(key, {"bytes": 0, "sessions": 0})
            entry["bytes"] += b
            entry["sessions"] += sess
        return out

    async def _top_countries_sampled(
        self,
        start_ts: int,
        stop_ts: int,
        limit: int = 15,
        expression: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Legacy fallback: aggregate srcGEO/dstGEO across the top
        _COUNTRY_SAMPLE sessions by bytes. Byte-biased (heavy flows dominate)
        and capped at a sample, which is exactly why spigraph is preferred — but
        it keeps geo data flowing on Arkime builds without /api/spigraph."""
        params = {
            "length": str(self._COUNTRY_SAMPLE),
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
            "order": "totBytes:desc",
            # Only request real SPI field names. `country.src`/`country.dst` are
            # expression aliases, not DB field names, and some viewer builds
            # 400 the WHOLE query when they appear in `fields=` — which emptied
            # the geo map entirely. `_geo_code` still reads srcGEO/dstGEO OR the
            # nested country{} shape on the response side.
            "fields": "srcGEO,dstGEO,totBytes",
        }
        if expression:
            params["expression"] = expression
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
                src_geo = self._geo_code(s, "src")
                dst_geo = self._geo_code(s, "dst")
                b = int(s.get("totBytes") or 0)
                if src_geo:
                    entry = src_map.setdefault(src_geo, {"bytes": 0, "sessions": 0})
                    entry["bytes"] += b
                    entry["sessions"] += 1
                if dst_geo:
                    entry = dst_map.setdefault(dst_geo, {"bytes": 0, "sessions": 0})
                    entry["bytes"] += b
                    entry["sessions"] += 1

            return {
                "by_src": self._rank_countries(src_map, limit),
                "by_dst": self._rank_countries(dst_map, limit),
            }
        except ArkimeError:
            raise
        except httpx.HTTPError as e:
            raise ArkimeError(f"Arkime top-countries error: {type(e).__name__}: {e}") from e

    async def get_per_node_traffic(
        self,
        start_ts: int,
        stop_ts: int,
        expression: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Aggregate traffic volume per Arkime capture node for the time window.

        Primary path is server-side ``/api/spigraph?field=node`` (unbiased,
        whole-window); falls back to the legacy session sample when spigraph is
        unavailable. ``method`` says which path produced the numbers.

        Returns:
            {
                "nodes": [{"node": "dc-core-01", "bytes": N, "sessions": N}, ...],
                "method": "spigraph" | "sample",
            }
            Sorted descending by bytes.
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        try:
            buckets = await self._spigraph_buckets("node", start_ts, stop_ts, expression)
            if buckets:
                nodes = sorted(
                    [{"node": n, **stats} for n, stats in buckets.items()],
                    key=lambda x: (x["bytes"], x["sessions"]),
                    reverse=True,
                )
                return {"nodes": nodes, "method": "spigraph"}
            logger.debug("Arkime spigraph returned no node buckets — falling back to sampling")
        except (ArkimeError, httpx.HTTPError) as exc:
            logger.debug("Arkime spigraph node aggregation failed (%s) — falling back to sampling", exc)
        out = await self._per_node_sampled(start_ts, stop_ts, expression)
        out["method"] = "sample"
        return out

    async def _per_node_sampled(
        self,
        start_ts: int,
        stop_ts: int,
        expression: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Legacy fallback: per-node volume from a top-_COUNTRY_SAMPLE session
        sample. Byte-biased and capped — spigraph is preferred."""
        params = {
            "length": str(self._COUNTRY_SAMPLE),
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
            "order": "totBytes:desc",
            "fields": "node,totBytes",
        }
        if expression:
            params["expression"] = expression
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

    _CONVO_SAMPLE = 1000  # sessions fetched for edge enrichment / graph fallback
    _PROTO_NAME_RE = re.compile(r"[a-z0-9._-]{1,32}")

    @classmethod
    def _clean_endpoint_ip(cls, value: Any) -> str:
        """Validated IP string for a conversation endpoint, or '' to drop.

        Endpoint values come straight off packet captures; round-tripping
        through ``ipaddress`` rejects garbage AND guarantees the value is safe
        to interpolate into Arkime expressions and DOM text downstream.
        """
        s = str(value or "").strip()
        if not s:
            return ""
        try:
            addr = ipaddress.ip_address(s)
        except ValueError:
            return ""
        if addr.is_link_local or addr.is_loopback or addr.is_unspecified:
            return ""
        return str(addr)

    @staticmethod
    def _packet_epoch(val: Any) -> Optional[float]:
        """firstPacket/lastPacket as float epoch seconds (ms on modern builds,
        seconds on older ones), or None when unparseable."""
        try:
            f = float(val)
        except (TypeError, ValueError):
            return None
        return f / 1000.0 if f > 10_000_000_000 else f

    async def get_conversations(
        self,
        start_ts: int,
        stop_ts: int,
        expression: Optional[str] = None,
        limit: int = 200,
    ) -> Dict[str, Any]:
        """Host-level conversation graph (src↔dst pairs) for the time window.

        Primary edge weights come from the viewer's ``/api/connections``
        aggregation — computed server-side over EVERY session in the window,
        no sample bias. One top-N-by-bytes session sample enriches those edges
        with dominant protocol / dst port / throughput (connections carries no
        per-edge protocol detail); when ``/api/connections`` is unavailable the
        same sample becomes the whole graph. ``method`` says which path
        produced the edge weights ("connections" | "sample").

        Returns:
            {
                "nodes": [{"ip", "bytes", "sessions"}, ...],
                "edges": [{"src", "dst", "bytes", "sessions", "packets",
                           "protocol", "port", "throughput_bps"}, ...],
                "method": "connections" | "sample",
            }
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        pair_edges = self._pair_edges(
            await self._conversations_sample(start_ts, stop_ts, expression)
        )
        by_pair = {(e["src"], e["dst"]): e for e in pair_edges}
        conn_edges: List[Dict[str, Any]] = []
        try:
            conn_edges = await self._connections_graph(start_ts, stop_ts, expression)
        except (ArkimeError, httpx.HTTPError) as exc:
            logger.debug(
                "Arkime /api/connections failed (%s) — building graph from sample", exc
            )
        if conn_edges:
            merged: List[Dict[str, Any]] = []
            for e in conn_edges:
                enr = by_pair.get((e["src"], e["dst"])) or by_pair.get((e["dst"], e["src"]))
                # Builds whose connections links omit byte sizes report 0 —
                # borrow the (sampled, byte-biased) figure so sizing still works.
                merged.append({
                    **e,
                    "bytes": e["bytes"] or (enr["bytes"] if enr else 0),
                    "packets": enr["packets"] if enr else 0,
                    "protocol": enr["protocol"] if enr else "",
                    "port": enr["port"] if enr else None,
                    "throughput_bps": enr["throughput_bps"] if enr else None,
                })
            edges, method = merged, "connections"
        else:
            edges, method = pair_edges, "sample"
        edges = sorted(edges, key=lambda x: (x["bytes"], x["sessions"]), reverse=True)[:limit]
        node_map: Dict[str, Dict[str, int]] = {}
        for e in edges:
            for ip in (e["src"], e["dst"]):
                entry = node_map.setdefault(ip, {"bytes": 0, "sessions": 0})
                entry["bytes"] += e["bytes"]
                entry["sessions"] += e["sessions"]
        nodes = sorted(
            [{"ip": ip, **stats} for ip, stats in node_map.items()],
            key=lambda x: (x["bytes"], x["sessions"]),
            reverse=True,
        )
        return {"nodes": nodes, "edges": edges, "method": method}

    async def _connections_graph(
        self,
        start_ts: int,
        stop_ts: int,
        expression: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Raw src↔dst edges from ``/api/connections``.

        Links reference nodes by integer index on every known build, but some
        inline the value — read both. Byte volume lives under ``by`` (viewer
        naming) with ``totBytes``/``size`` fallbacks; session count under
        ``value``/``count``/``sessions``. Raises ArkimeError on non-200 /
        non-JSON so the caller can fall back to the session sample.
        """
        params = {
            "srcField": "ip.src",
            "dstField": "ip.dst",
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
            "minConn": "1",
        }
        if expression:
            params["expression"] = expression
        headers = await self._headers()
        async with await self._client() as client:
            resp = await client.get(
                f"{self.url}/api/connections", headers=headers, params=params
            )
        if resp.status_code != 200:
            raise ArkimeError(
                f"Arkime connections failed: HTTP {resp.status_code}",
                status_code=resp.status_code,
            )
        if "json" not in resp.headers.get("content-type", ""):
            raise ArkimeError("Arkime returned non-JSON — check auth")
        payload = resp.json()
        ids: List[str] = []
        for n in payload.get("nodes") or []:
            node_id = n.get("id") if isinstance(n, dict) else n
            ids.append(str(node_id) if node_id is not None else "")

        def _endpoint(ref: Any) -> str:
            if isinstance(ref, int):
                raw = ids[ref] if 0 <= ref < len(ids) else ""
            else:
                raw = ref
            return self._clean_endpoint_ip(raw)

        edges: List[Dict[str, Any]] = []
        for ln in payload.get("links") or []:
            if not isinstance(ln, dict):
                continue
            src = _endpoint(ln.get("source"))
            dst = _endpoint(ln.get("target"))
            if not src or not dst or src == dst:
                continue
            try:
                b = int(ln.get("by") or ln.get("totBytes") or ln.get("size") or 0)
            except (TypeError, ValueError):
                b = 0
            try:
                sess = int(ln.get("value") or ln.get("count") or ln.get("sessions") or 0)
            except (TypeError, ValueError):
                sess = 0
            edges.append({"src": src, "dst": dst, "bytes": b, "sessions": sess})
        return edges

    async def _conversations_sample(
        self,
        start_ts: int,
        stop_ts: int,
        expression: Optional[str] = None,
    ) -> Dict[Any, Dict[str, Any]]:
        """Pair-keyed aggregation of the top-``_CONVO_SAMPLE``-by-bytes
        sessions. Byte-biased and capped — which is why ``/api/connections``
        supplies the edge weights when available — but it is the only source of
        per-edge protocol / port / duration. Degrades to {} on any failure so
        the connections path still renders unenriched.
        """
        params = {
            "length": str(self._CONVO_SAMPLE),
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
            "order": "totBytes:desc",
            "fields": "srcIp,dstIp,totBytes,packets,ipProtocol,dstPort,firstPacket,lastPacket",
        }
        if expression:
            params["expression"] = expression
        headers = await self._headers()
        try:
            async with await self._client() as client:
                resp = await client.get(
                    f"{self.url}/api/sessions", headers=headers, params=params
                )
            if resp.status_code != 200 or "json" not in resp.headers.get("content-type", ""):
                return {}
            sessions = resp.json().get("data") or []
        except httpx.HTTPError:
            return {}
        pairs: Dict[Any, Dict[str, Any]] = {}
        for s in sessions:
            src = self._clean_endpoint_ip(s.get("srcIp") or s.get("source", {}).get("ip", ""))
            dst = self._clean_endpoint_ip(s.get("dstIp") or s.get("destination", {}).get("ip", ""))
            if not src or not dst or src == dst:
                continue
            try:
                b = int(s.get("totBytes") or 0)
            except (TypeError, ValueError):
                b = 0
            pk_raw = s.get("packets")
            if isinstance(pk_raw, (list, tuple)):
                pk = sum(int(p) for p in pk_raw if isinstance(p, (int, float)))
            else:
                try:
                    pk = int(pk_raw or 0)
                except (TypeError, ValueError):
                    pk = 0
            ipp = s.get("ipProtocol")
            proto = (
                self._IPPROTO_NAMES.get(ipp) if isinstance(ipp, int)
                else (str(ipp).strip().lower() if ipp else "")
            ) or ""
            if proto and not self._PROTO_NAME_RE.fullmatch(proto):
                proto = ""
            port: Optional[int] = None
            try:
                p = int(s.get("dstPort"))
                if 0 <= p <= 65535:
                    port = p
            except (TypeError, ValueError):
                pass
            first = self._packet_epoch(s.get("firstPacket"))
            last = self._packet_epoch(s.get("lastPacket"))
            entry = pairs.setdefault((src, dst), {
                "bytes": 0, "sessions": 0, "packets": 0,
                "protocols": {}, "ports": {}, "first": None, "last": None,
            })
            entry["bytes"] += b
            entry["sessions"] += 1
            entry["packets"] += pk
            if proto:
                entry["protocols"][proto] = entry["protocols"].get(proto, 0) + b
            if port is not None:
                entry["ports"][port] = entry["ports"].get(port, 0) + b
            if first is not None:
                entry["first"] = first if entry["first"] is None else min(entry["first"], first)
            if last is not None:
                entry["last"] = last if entry["last"] is None else max(entry["last"], last)
        return pairs

    @staticmethod
    def _pair_edges(pairs: Dict[Any, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Pair aggregates → edge dicts: dominant protocol/port by byte share,
        throughput from bytes ÷ observed packet span (None when the span is
        zero or unknown — never fake a rate)."""
        edges: List[Dict[str, Any]] = []
        for (src, dst), st in pairs.items():
            protocols = st.get("protocols") or {}
            ports = st.get("ports") or {}
            span = (
                st["last"] - st["first"]
                if st.get("first") is not None and st.get("last") is not None
                else 0
            )
            edges.append({
                "src": src,
                "dst": dst,
                "bytes": st["bytes"],
                "sessions": st["sessions"],
                "packets": st["packets"],
                "protocol": max(protocols, key=protocols.get) if protocols else "",
                "port": max(ports, key=ports.get) if ports else None,
                "throughput_bps": round(st["bytes"] / span, 1) if span > 0 else None,
            })
        return edges

    async def _oldest_session_epoch(
        self, expression: Optional[str], start_ts: int, stop_ts: int
    ) -> Optional[int]:
        """Epoch seconds of the oldest session in the window matching
        ``expression`` (None = whole capture), or None when nothing matches /
        the query fails. One length-1 ascending query — cheap on any build."""
        params = {
            "length": "1",
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
            "order": "firstPacket:asc",
            "fields": "node,firstPacket",
        }
        if expression:
            params["expression"] = expression
        headers = await self._headers()
        try:
            async with await self._client() as client:
                resp = await client.get(
                    f"{self.url}/api/sessions", headers=headers, params=params
                )
            if resp.status_code != 200 or "json" not in resp.headers.get("content-type", ""):
                return None
            data = resp.json().get("data") or []
            if not data:
                return None
            fp = data[0].get("firstPacket")
            # firstPacket is epoch milliseconds on modern builds; tolerate
            # second-resolution values from older ones.
            val = float(fp)
            return int(val / 1000.0) if val > 10_000_000_000 else int(val)
        except (httpx.HTTPError, TypeError, ValueError):
            return None

    async def get_retention_horizons(
        self, *, lookback_days: int = 60, max_nodes: int = 10
    ) -> Dict[str, int]:
        """Oldest-available capture time (epoch seconds) per node, plus ``"*"``
        for the whole cluster. Sessions older than a node's horizon have aged
        out of PCAP retention — the analysis window for their cases is closed.

        Empty dict when Arkime is unreachable or holds no sessions in the
        lookback window; callers must treat that as "horizon unknown", not
        "everything expired".
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        now = int(time.time())
        start = now - lookback_days * 86400
        horizons: Dict[str, int] = {}
        cluster = await self._oldest_session_epoch(None, start, now)
        if cluster is not None:
            horizons["*"] = cluster
        try:
            buckets = await self._spigraph_buckets("node", now - 7 * 86400, now)
        except (ArkimeError, httpx.HTTPError):
            buckets = {}
        for node in sorted(buckets)[:max_nodes]:
            oldest = await self._oldest_session_epoch(
                f'node == "{escape_arkime_quoted(node)}"', start, now
            )
            if oldest is not None:
                horizons[node] = oldest
        return horizons

    # ── Hunts (packet search) ─────────────────────────────────────────────
    _HUNT_SEARCH_TYPES = ("ascii", "asciicase", "hex", "regex", "hexregex")

    async def create_hunt(
        self,
        *,
        name: str,
        search: str,
        search_type: str = "ascii",
        expression: Optional[str] = None,
        start_ts: int,
        stop_ts: int,
        size: int = 1000,
    ) -> Dict[str, Any]:
        """Submit a packet-search (hunt) job to the viewer.

        Requires the configured Arkime user to hold the ``packetSearch``
        permission; without it the viewer returns 403. Returns
        ``{"id": <arkime hunt id or None>, "raw": <response payload>}``.
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        if search_type not in self._HUNT_SEARCH_TYPES:
            raise ArkimeError(f"Invalid hunt search type {search_type!r}")
        body: Dict[str, Any] = {
            "name": name,
            "size": max(1, min(int(size), 10_000)),
            "search": search,
            "searchType": search_type,
            "src": True,
            "dst": True,
            "type": "reassembled",
            "query": {
                "startTime": int(start_ts),
                "stopTime": int(stop_ts),
                "expression": expression or "",
            },
        }
        headers = await self._headers({"Content-Type": "application/json"})
        try:
            async with await self._client() as client:
                resp = await client.post(
                    f"{self.url}/api/hunt", headers=headers, json=body
                )
            if resp.status_code == 403:
                raise ArkimeError(
                    "Arkime refused the hunt (HTTP 403) — the ION service user "
                    "needs the packetSearch permission",
                    status_code=403,
                )
            if resp.status_code != 200:
                raise ArkimeError(
                    f"Arkime hunt submission failed: HTTP {resp.status_code}: "
                    f"{(resp.text or '')[:200]}",
                    status_code=resp.status_code,
                )
            try:
                payload = resp.json()
            except ValueError:
                raise ArkimeError("Arkime hunt response is not JSON — check auth")
            if payload.get("success") is False:
                raise ArkimeError(
                    f"Arkime rejected the hunt: {payload.get('text') or 'unknown error'}"
                )
            hunt_obj = payload.get("hunt") if isinstance(payload.get("hunt"), dict) else {}
            hunt_id = hunt_obj.get("id") or payload.get("id")
            return {"id": str(hunt_id) if hunt_id else None, "raw": payload}
        except ArkimeError:
            raise
        except httpx.HTTPError as e:
            raise ArkimeError(f"Arkime hunt error: {type(e).__name__}: {e}") from e

    async def list_hunts(self) -> List[Dict[str, Any]]:
        """All hunt jobs the viewer reports (running + history). Each item
        carries at least ``id``/``status``; ``matchedSessions`` where the
        build reports it. Shapes vary across versions — read defensively."""
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        headers = await self._headers()
        try:
            async with await self._client() as client:
                resp = await client.get(f"{self.url}/api/hunts", headers=headers)
            if resp.status_code != 200:
                raise ArkimeError(
                    f"Arkime hunt list failed: HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            if "json" not in resp.headers.get("content-type", ""):
                raise ArkimeError("Arkime returned non-JSON — check auth")
            payload = resp.json()
            hunts = list(payload.get("data") or [])
            running = payload.get("runningJob")
            if isinstance(running, dict) and running.get("id") not in {
                h.get("id") for h in hunts
            }:
                hunts.append(running)
            return hunts
        except ArkimeError:
            raise
        except httpx.HTTPError as e:
            raise ArkimeError(f"Arkime hunt list error: {type(e).__name__}: {e}") from e

    async def get_hunt(self, hunt_id: str) -> Optional[Dict[str, Any]]:
        """One hunt job by Arkime id, or None. List-and-filter — there is no
        stable per-id endpoint across viewer versions."""
        for h in await self.list_hunts():
            if str(h.get("id") or "") == str(hunt_id):
                return h
        return None

    async def add_session_tags(
        self, expression: str, tags: List[str], start_ts: int, stop_ts: int
    ) -> bool:
        """Tag every session matching ``expression`` in the window
        (``POST /api/sessions/addtags``). Requires a write-enabled Arkime
        user. Returns True on success; raises ArkimeError otherwise."""
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        clean = [t.strip() for t in tags if t and t.strip()]
        if not clean or not expression:
            return False
        body = {
            "tags": ",".join(clean),
            "expression": expression,
            "startTime": int(start_ts),
            "stopTime": int(stop_ts),
        }
        headers = await self._headers({"Content-Type": "application/json"})
        try:
            async with await self._client() as client:
                resp = await client.post(
                    f"{self.url}/api/sessions/addtags", headers=headers, json=body
                )
            if resp.status_code == 403:
                raise ArkimeError(
                    "Arkime refused the tag write (HTTP 403) — the ION service "
                    "user is read-only",
                    status_code=403,
                )
            if resp.status_code != 200:
                raise ArkimeError(
                    f"Arkime tag write failed: HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            return True
        except ArkimeError:
            raise
        except httpx.HTTPError as e:
            raise ArkimeError(f"Arkime tag write error: {type(e).__name__}: {e}") from e

    async def stream_sessions_pcap(
        self, expression: str, start_ts: int, stop_ts: int
    ):
        """Open a streaming download of the merged PCAP for every session
        matching ``expression`` in the window (``/api/sessions/pcap``).

        Returns an async byte iterator that owns the HTTP client/response and
        closes both when exhausted or dropped. Nothing is buffered server-side
        beyond httpx's chunk — ION never stores raw PCAP.
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        params = {
            "expression": expression,
            "startTime": str(start_ts),
            "stopTime": str(stop_ts),
        }
        headers = await self._headers({"Accept": "application/vnd.tcpdump.pcap"})
        client = await self._pcap_client()
        try:
            req = client.build_request(
                "GET", f"{self.url}/api/sessions/pcap", params=params, headers=headers
            )
            resp = await client.send(req, stream=True)
        except httpx.HTTPError as e:
            await client.aclose()
            raise ArkimeError(
                f"Arkime merged-PCAP error: {type(e).__name__}: {e}"
            ) from e
        if resp.status_code != 200:
            await resp.aclose()
            await client.aclose()
            raise ArkimeError(
                f"Arkime merged-PCAP download failed: HTTP {resp.status_code}",
                status_code=resp.status_code,
            )

        async def _iter():
            try:
                async for chunk in resp.aiter_bytes():
                    yield chunk
            finally:
                await resp.aclose()
                await client.aclose()

        return _iter()

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

        # URL-encode the node path segment — it comes from alert data and must
        # not be able to inject extra path segments or query into the request.
        url = f"{self.url}/api/session/{quote(str(node), safe='')}/{session_id}/pcap"
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


def _audit_tag_writeback(case_number: Any, cids: List[str]) -> None:
    """Best-effort audit_logs row for the Arkime tag write — ION's only
    outbound mutation into Arkime deserves a forensic trail beyond app logs."""
    try:
        from ion.models.user import AuditLog
        from ion.storage.database import get_session_factory

        session = get_session_factory()()
        try:
            session.add(AuditLog(
                user_id=None, action="arkime_tag_writeback",
                resource_type="alert_case", resource_id=None,
                details=f"{case_number}: tagged {len(cids)} flow(s) ion-{str(case_number).strip().lower()}",
            ))
            session.commit()
        finally:
            session.close()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Arkime tag write-back audit row failed: %s", exc)


def spawn_case_tag_writeback(case_number: Optional[str], community_ids: List[str]) -> None:
    """Best-effort: tag the case's Arkime sessions ``ion`` +
    ``ion-<case-number>`` so the pivot works from the viewer side too.

    Behind ``ION_ARKIME_TAG_WRITEBACK`` (default OFF — this is ION's only
    write into Arkime, and it needs a write-enabled viewer user). Runs on a
    daemon thread with its own event loop so sync case-creation paths can
    fire-and-forget; a failure logs at debug and never touches the case flow.
    """
    if os.environ.get("ION_ARKIME_TAG_WRITEBACK", "").strip().lower() not in (
        "true", "1", "yes", "on"
    ):
        return
    cids = [c.strip() for c in (community_ids or []) if c and c.strip()][:20]
    if not case_number or not cids:
        return

    def _worker() -> None:
        import asyncio

        try:
            svc = get_arkime_service()
            if not svc.is_configured:
                return
            expression = " || ".join(
                f'communityId == "{escape_arkime_quoted(c)}"' for c in cids
            )
            now = int(time.time())
            asyncio.run(svc.add_session_tags(
                expression,
                ["ion", f"ion-{str(case_number).strip().lower()}"],
                now - 7 * 86400,
                now,
            ))
            logger.info("Arkime tag write-back: tagged %d flow(s) for %s", len(cids), case_number)
            _audit_tag_writeback(case_number, cids)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Arkime tag write-back failed for %s: %s", case_number, exc)

    import threading

    threading.Thread(target=_worker, daemon=True, name="arkime-tag-writeback").start()


def arkime_public_url() -> str:
    """Base viewer URL for analyst-browser deep links.

    ``ION_ARKIME_PUBLIC_URL`` when set (the server-side ``ION_ARKIME_URL`` is
    often an internal address the analyst's browser can't reach), otherwise
    the configured service URL. Empty string when Arkime is unconfigured —
    callers omit the link in that case.
    """
    public = os.environ.get("ION_ARKIME_PUBLIC_URL", "").strip().rstrip("/")
    if public:
        return public
    return get_arkime_service().url or ""


def arkime_sessions_link(expression: str) -> str:
    """Deep link into the Arkime sessions view for an expression, or ''."""
    base = arkime_public_url()
    if not base:
        return ""
    return f"{base}/sessions?expression={quote(expression, safe='')}"


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
