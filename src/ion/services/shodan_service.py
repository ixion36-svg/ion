"""Shodan REST API integration service for ION.

Provides IP-address enrichment (open ports, hostnames, org, country,
known CVEs) by querying the Shodan host endpoint.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx

from ion.core.config import get_config, get_ssl_verify

logger = logging.getLogger(__name__)


class ShodanError(Exception):
    """Exception raised for Shodan API errors."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class ShodanService:
    """Async client for the Shodan REST API."""

    DEFAULT_URL = "https://api.shodan.io"
    DEFAULT_TIMEOUT = 30

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: Optional[int] = None,
    ):
        """Initialize the Shodan service.

        Values fall back to configuration (and then to environment variables)
        when not provided, so the service works even if the Config dataclass
        has not yet been extended with the new Shodan fields.
        """
        config = get_config()

        resolved_url = (
            url
            or getattr(config, "shodan_url", "")
            or os.environ.get("ION_SHODAN_URL", "")
            or self.DEFAULT_URL
        )
        self.url = resolved_url.rstrip("/")

        self.api_key = (
            api_key
            if api_key is not None
            else getattr(config, "shodan_api_key", "")
            or os.environ.get("ION_SHODAN_API_KEY", "")
        )

        if verify_ssl is None:
            verify_ssl = getattr(config, "shodan_verify_ssl", None)
            if verify_ssl is None:
                env_verify = os.environ.get("ION_SHODAN_VERIFY_SSL")
                verify_ssl = (env_verify.lower() in ("1", "true", "yes")) if env_verify else True
        self.verify_ssl = bool(verify_ssl)

        if timeout is None:
            timeout = getattr(config, "shodan_timeout", None)
            if timeout is None:
                env_timeout = os.environ.get("ION_SHODAN_TIMEOUT")
                timeout = int(env_timeout) if env_timeout else self.DEFAULT_TIMEOUT
        self.timeout = int(timeout)

        self.enabled = bool(
            getattr(config, "shodan_enabled", False)
            or os.environ.get("ION_SHODAN_ENABLED", "").lower() in ("1", "true", "yes")
        )

    @property
    def is_configured(self) -> bool:
        """True when an API key is configured."""
        return bool(self.api_key)

    async def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Issue a GET to the Shodan REST API.

        Returns the parsed JSON body on 200, ``None`` on 404.

        Raises:
            ShodanError: on other error responses.
        """
        if not self.is_configured:
            raise ShodanError("Shodan integration is not configured")

        request_params: Dict[str, Any] = dict(params or {})
        request_params["key"] = self.api_key

        full_url = f"{self.url}{path}"
        try:
            async with httpx.AsyncClient(
                verify=get_ssl_verify(self.verify_ssl),
                timeout=httpx.Timeout(float(self.timeout), connect=10.0),
            ) as client:
                response = await client.get(
                    full_url,
                    params=request_params,
                    headers={"Accept": "application/json"},
                )
        except httpx.ConnectError as exc:
            raise ShodanError(f"Failed to connect to Shodan: {exc}")
        except httpx.TimeoutException as exc:
            raise ShodanError(f"Request to Shodan timed out: {exc}")
        except httpx.HTTPError as exc:
            raise ShodanError(f"HTTP error communicating with Shodan: {exc}")

        status = response.status_code
        if status == 200:
            try:
                return response.json()
            except ValueError as exc:
                raise ShodanError(f"Shodan returned invalid JSON: {exc}")
        if status == 404:
            return None
        if status == 401:
            raise ShodanError("Shodan API key is invalid or missing", status_code=401)

        try:
            error_data = response.json()
            message = str(error_data.get("error", error_data))
        except ValueError:
            message = response.text
        raise ShodanError(f"Shodan API error ({status}): {message}", status_code=status)

    def _normalize(self, raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Convert a Shodan host response (or None) into the uniform shape."""
        if not raw:
            return {
                "found": False,
                "open_ports": [],
                "hostnames": [],
                "country": "",
                "org": "",
                "os": None,
                "vulns": [],
                "last_update": None,
                "raw": {},
                "source": "shodan",
            }

        # Ports — Shodan returns a list of ints under "ports" (sometimes absent)
        raw_ports = raw.get("ports") or []
        open_ports: List[int] = []
        for port in raw_ports:
            try:
                open_ports.append(int(port))
            except (TypeError, ValueError):
                continue

        hostnames = [h for h in (raw.get("hostnames") or []) if isinstance(h, str)]

        vulns_field = raw.get("vulns")
        if isinstance(vulns_field, dict):
            vulns: List[str] = list(vulns_field.keys())
        elif isinstance(vulns_field, list):
            vulns = [str(v) for v in vulns_field]
        else:
            vulns = []

        return {
            "found": True,
            "open_ports": open_ports,
            "hostnames": hostnames,
            "country": raw.get("country_name") or raw.get("country_code") or "",
            "org": raw.get("org") or "",
            "os": raw.get("os"),
            "vulns": vulns,
            "last_update": raw.get("last_update"),
            "raw": raw,
            "source": "shodan",
        }

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up an IP address via /shodan/host/{ip}."""
        if not ip:
            raise ShodanError("Empty IP address")
        raw = await self._get(f"/shodan/host/{ip}")
        return self._normalize(raw)


# Singleton instance
_shodan_service: Optional[ShodanService] = None


def get_shodan_service() -> ShodanService:
    """Get the global Shodan service instance."""
    global _shodan_service
    if _shodan_service is None:
        _shodan_service = ShodanService()
    return _shodan_service


def reset_shodan_service() -> None:
    """Reset the global Shodan service instance (for config changes)."""
    global _shodan_service
    _shodan_service = None
