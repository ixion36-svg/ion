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

Authentication
--------------
Arkime is deployed behind Keycloak SSO, so the preferred auth mode is an
OAuth2 client_credentials grant against Keycloak to obtain a bearer token,
then `Authorization: Bearer <token>` on every Arkime request. The token is
cached in memory until ~30 s before its `exp` claim.

Configuration (`.env`):
    ION_ARKIME_URL=https://viewer.guardedglass.internal
    ION_ARKIME_KEYCLOAK_ISSUER=https://keycloak.guardedglass.internal/realms/soc
    ION_ARKIME_KEYCLOAK_CLIENT_ID=ion-arkime-client
    ION_ARKIME_KEYCLOAK_CLIENT_SECRET=…
    ION_ARKIME_KEYCLOAK_SCOPE=openid
    ION_ARKIME_VERIFY_SSL=true|false

For dev / non-SSO setups, basic auth or `Digest <key>` are still honoured via
`ION_ARKIME_USERNAME`/`ION_ARKIME_PASSWORD`/`ION_ARKIME_API_KEY`, but Keycloak
takes precedence when configured.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

import httpx

from ion.core.config import get_arkime_config

logger = logging.getLogger(__name__)

# Shared persistent httpx client — avoids per-request connection overhead.
_arkime_client: Optional[httpx.AsyncClient] = None


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

    def _auth(self):
        """Kept for call-site compatibility — returns None now.

        Previously returned ``httpx.BasicAuth`` / ``httpx.DigestAuth``
        objects, but we now send credentials exclusively via the
        ``Authorization`` header (see :meth:`_headers`). Passing
        ``auth=None`` to httpx is a no-op.
        """
        return None

    async def _client(self) -> httpx.AsyncClient:
        # Fresh client per request — Arkime's digest auth requires a fresh
        # 401 challenge-response per connection. Shared clients cause stale
        # nonce errors after the first request.
        return httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=60.0,
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
                    auth=self._auth(),
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
                    auth=self._auth(),
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
            raise ArkimeError(f"Arkime session search error: {e}") from e

    async def find_sessions_by_ip(
        self,
        node: str,
        ip: str,
        *,
        hours: int = 1,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Search Arkime for sessions involving an IP within a time window.

        Fallback when community_id is not available on the alert. Searches
        both source and destination so any traffic involving the IP is found.
        When *node* is empty the node filter is omitted.
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        expression = f'(ip.src == {ip} || ip.dst == {ip})'
        if node:
            expression += f' && node == "{node}"'
        params = {
            "expression": expression,
            "length": str(limit),
            "startTime": str(int(time.time() - hours * 3600)),
            "stopTime": str(int(time.time())),
            "fields": self._SESSION_FIELDS,
        }
        headers = await self._headers()
        try:
            async with await self._client() as client:
                resp = await client.get(
                    f"{self.url}/api/sessions",
                    auth=self._auth(),
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
            raise ArkimeError(f"Arkime IP session search error: {e}") from e

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
        # Emitted at INFO so `docker compose logs ion | grep "Arkime PCAP GET"`
        # surfaces the exact URL being requested — useful for debugging 404s
        # caused by node-name or session-id format mismatches.
        logger.info("Arkime PCAP GET %s (auth scheme=%s)", url,
                    headers.get("Authorization", "").split(" ", 1)[0] or "none")
        try:
            async with await self._client() as client:
                resp = await client.get(
                    url,
                    auth=self._auth(),
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
            raise ArkimeError(f"Arkime PCAP download error: {e}") from e


# Singleton
_arkime_service: Optional[ArkimeService] = None


def get_arkime_service() -> ArkimeService:
    global _arkime_service
    if _arkime_service is None:
        _arkime_service = ArkimeService()
    return _arkime_service


def reset_arkime_service() -> None:
    global _arkime_service, _arkime_client
    _arkime_service = None
    if _arkime_client is not None and not _arkime_client.is_closed:
        try:
            import asyncio
            loop = asyncio.get_running_loop()
            loop.create_task(_arkime_client.aclose())
        except RuntimeError:
            pass
    _arkime_client = None
