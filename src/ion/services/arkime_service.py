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


class ArkimeError(Exception):
    """Raised for any Arkime viewer API failure."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class ArkimeService:
    """Thin async client for the Arkime viewer API.

    Holds a cached OAuth2 access token but no persistent HTTP client — each
    request opens its own short-lived AsyncClient. Multiple concurrent
    requests may each trigger a token refresh if the cached token is stale;
    that's harmless because Keycloak returns a fresh token per call and the
    cache is last-write-wins.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        keycloak_issuer: Optional[str] = None,
        keycloak_client_id: Optional[str] = None,
        keycloak_client_secret: Optional[str] = None,
        keycloak_scope: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
    ):
        config = get_arkime_config()
        self.url = (url if url is not None else config.get("url", "")).rstrip("/")
        self.keycloak_issuer = (
            keycloak_issuer
            if keycloak_issuer is not None
            else config.get("keycloak_issuer", "")
        ).rstrip("/")
        self.keycloak_client_id = (
            keycloak_client_id
            if keycloak_client_id is not None
            else config.get("keycloak_client_id", "")
        )
        self.keycloak_client_secret = (
            keycloak_client_secret
            if keycloak_client_secret is not None
            else config.get("keycloak_client_secret", "")
        )
        self.keycloak_scope = (
            keycloak_scope
            if keycloak_scope is not None
            else config.get("keycloak_scope", "openid")
        )
        self.username = username if username is not None else config.get("username", "")
        self.password = password if password is not None else config.get("password", "")
        self.api_key = api_key if api_key is not None else config.get("api_key", "")
        self.verify_ssl = verify_ssl if verify_ssl is not None else config.get("verify_ssl", True)

        # OAuth2 token cache
        self._access_token: Optional[str] = None
        self._token_expires_at: float = 0.0  # unix seconds

    @property
    def _has_keycloak(self) -> bool:
        return bool(
            self.keycloak_issuer
            and self.keycloak_client_id
            and self.keycloak_client_secret
        )

    @property
    def _has_basic(self) -> bool:
        return bool(self.username and self.password)

    @property
    def is_configured(self) -> bool:
        return bool(
            self.url and (self._has_keycloak or self.api_key or self._has_basic)
        )

    # ── Keycloak client_credentials grant ──────────────────────────────────
    async def _get_access_token(self) -> str:
        """Return a cached or freshly-minted Keycloak access token."""
        now = time.time()
        if self._access_token and (self._token_expires_at - 30) > now:
            return self._access_token

        token_url = f"{self.keycloak_issuer}/protocol/openid-connect/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.keycloak_client_id,
            "client_secret": self.keycloak_client_secret,
        }
        if self.keycloak_scope:
            data["scope"] = self.keycloak_scope

        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=20.0) as client:
                resp = await client.post(token_url, data=data)
        except httpx.HTTPError as e:
            raise ArkimeError(f"Keycloak token request failed: {e}") from e

        if resp.status_code != 200:
            detail = ""
            try:
                payload = resp.json()
                detail = payload.get("error_description") or payload.get("error") or ""
            except ValueError:
                detail = resp.text[:200]
            raise ArkimeError(
                f"Keycloak token request failed: HTTP {resp.status_code} {detail}".strip(),
                status_code=resp.status_code,
            )
        payload = resp.json()
        token = payload.get("access_token")
        expires_in = int(payload.get("expires_in", 60))
        if not token:
            raise ArkimeError("Keycloak response missing access_token")
        self._access_token = token
        self._token_expires_at = now + expires_in
        return token

    async def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Build request headers — Keycloak Bearer → Digest key → (basic on request)."""
        headers: Dict[str, str] = {"Accept": "application/json"}
        if self._has_keycloak:
            token = await self._get_access_token()
            headers["Authorization"] = f"Bearer {token}"
        elif self.api_key:
            headers["Authorization"] = f"Digest {self.api_key}"
        if extra:
            headers.update(extra)
        return headers

    def _auth(self) -> Optional[httpx.BasicAuth]:
        """Only used for dev/non-SSO basic-auth setups."""
        if self._has_keycloak or self.api_key:
            return None
        if self._has_basic:
            return httpx.BasicAuth(self.username, self.password)
        return None

    async def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=60.0,  # PCAP downloads can be slow
            follow_redirects=True,
        )

    # ── Probes ─────────────────────────────────────────────────────────────
    async def test_connection(self) -> Dict[str, Any]:
        """Verify we can talk to Arkime. Returns status dict for the UI.

        With Keycloak auth this doubles as a Keycloak liveness check — the
        token fetch happens before the Arkime call.
        """
        if not self.is_configured:
            return {"connected": False, "error": "Arkime is not configured"}
        try:
            headers = await self._headers()
        except ArkimeError as e:
            return {"connected": False, "url": self.url, "error": str(e)}
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
                    "user": data.get("userId") or self.keycloak_client_id or self.username or "",
                    "auth_mode": (
                        "keycloak" if self._has_keycloak
                        else "api_key" if self.api_key
                        else "basic"
                    ),
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
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        expression = f'communityId == "{community_id}" && node == "{node}"'
        params = {
            "expression": expression,
            "length": str(limit),
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
                raise ArkimeError(
                    f"Arkime session search failed: HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            payload = resp.json()
            data = payload.get("data") if isinstance(payload, dict) else None
            if isinstance(data, list):
                return data
            return []
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
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        expression = f'(ip.src == {ip} || ip.dst == {ip}) && node == "{node}"'
        params = {
            "expression": expression,
            "length": str(limit),
            "startTime": str(int(((__import__("time").time()) - hours * 3600))),
            "stopTime": str(int(__import__("time").time())),
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
                raise ArkimeError(
                    f"Arkime IP session search failed: HTTP {resp.status_code}",
                    status_code=resp.status_code,
                )
            payload = resp.json()
            data = payload.get("data") if isinstance(payload, dict) else None
            return data if isinstance(data, list) else []
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
                f"No Arkime sessions matched community_id={community_id} on "
                f"node={node}",
                status_code=404,
            )
        primary = sessions[0]
        arkime_session_id = primary.get("id") or primary.get("_id")
        if not arkime_session_id:
            raise ArkimeError("Arkime session document missing `id` field")
        pcap_bytes = await self.download_pcap(node, str(arkime_session_id))
        return {
            "pcap": pcap_bytes,
            "session": primary,
            "other_matches": sessions[1:],
        }

    async def download_pcap(self, node: str, session_id: str) -> bytes:
        """Download the raw PCAP bytes for a single Arkime session.

        Arkime 5.x URL pattern:
            {base}/api/session/{node}/{sessionId}/pcap
        """
        if not self.is_configured:
            raise ArkimeError("Arkime is not configured")
        if not node or not session_id:
            raise ArkimeError("Both `node` and `session_id` are required")

        url = f"{self.url}/api/session/{node}/{session_id}/pcap"
        headers = await self._headers({"Accept": "application/vnd.tcpdump.pcap"})
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
    global _arkime_service
    _arkime_service = None
