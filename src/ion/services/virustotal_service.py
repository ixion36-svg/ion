"""VirusTotal v3 API integration service for ION.

Provides IOC enrichment by querying VirusTotal's public API for file hashes,
URLs, domains, and IP addresses. Normalizes results into a uniform shape
consumable by ION's enrichment API.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

from ion.core.config import get_config, get_ssl_verify

logger = logging.getLogger(__name__)


class VirusTotalError(Exception):
    """Exception raised for VirusTotal API errors."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class RateLimitedError(VirusTotalError):
    """Exception raised when VirusTotal rate limits the caller (HTTP 429)."""

    def __init__(self, message: str = "VirusTotal rate limit exceeded",
                 retry_after: Optional[float] = None):
        super().__init__(message, status_code=429)
        self.retry_after = retry_after


class InvalidKeyError(VirusTotalError):
    """Exception raised when the API key is rejected (HTTP 401)."""

    def __init__(self, message: str = "VirusTotal API key is invalid"):
        super().__init__(message, status_code=401)


def _to_iso8601(epoch: Optional[int]) -> Optional[str]:
    """Convert a UNIX epoch (seconds) to an ISO8601 UTC string."""
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def _encode_url_id(url: str) -> str:
    """Return the VirusTotal URL id (base64url of the URL without padding)."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


class VirusTotalService:
    """Async client for the VirusTotal v3 REST API."""

    DEFAULT_URL = "https://www.virustotal.com"
    DEFAULT_TIMEOUT = 30
    DEFAULT_RATE_LIMIT = 4  # requests per minute on the free tier

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: Optional[int] = None,
        rate_limit: Optional[int] = None,
    ):
        """Initialize the VirusTotal service.

        Values fall back to configuration (and then to environment variables)
        when not provided. This lets the service work even if the Config
        dataclass has not yet been extended with the new fields documented in
        the integration checklist.
        """
        config = get_config()

        # URL — config.virustotal_url > ION_VIRUSTOTAL_URL > default
        resolved_url = (
            url
            or getattr(config, "virustotal_url", "")
            or os.environ.get("ION_VIRUSTOTAL_URL", "")
            or self.DEFAULT_URL
        )
        self.url = resolved_url.rstrip("/")

        # API key — config.virustotal_api_key > ION_VIRUSTOTAL_API_KEY
        self.api_key = (
            api_key
            if api_key is not None
            else getattr(config, "virustotal_api_key", "")
            or os.environ.get("ION_VIRUSTOTAL_API_KEY", "")
        )

        # SSL verify
        if verify_ssl is None:
            verify_ssl = getattr(config, "virustotal_verify_ssl", None)
            if verify_ssl is None:
                env_verify = os.environ.get("ION_VIRUSTOTAL_VERIFY_SSL")
                verify_ssl = (env_verify.lower() in ("1", "true", "yes")) if env_verify else True
        self.verify_ssl = bool(verify_ssl)

        # Timeout
        if timeout is None:
            timeout = getattr(config, "virustotal_timeout", None)
            if timeout is None:
                env_timeout = os.environ.get("ION_VIRUSTOTAL_TIMEOUT")
                timeout = int(env_timeout) if env_timeout else self.DEFAULT_TIMEOUT
        self.timeout = int(timeout)

        # Rate limit (requests per minute)
        if rate_limit is None:
            rate_limit = getattr(config, "virustotal_rate_limit", None)
            if rate_limit is None:
                env_rl = os.environ.get("ION_VIRUSTOTAL_RATE_LIMIT")
                rate_limit = int(env_rl) if env_rl else self.DEFAULT_RATE_LIMIT
        self.rate_limit = max(1, int(rate_limit))

        # Enabled flag (informational only — callers decide whether to invoke)
        self.enabled = bool(
            getattr(config, "virustotal_enabled", False)
            or os.environ.get("ION_VIRUSTOTAL_ENABLED", "").lower() in ("1", "true", "yes")
        )

        # Sliding-window timestamps of recent request starts
        self._request_times: list[float] = []
        self._rate_lock = asyncio.Lock()

    @property
    def is_configured(self) -> bool:
        """True when an API key is configured."""
        return bool(self.api_key)

    def _get_headers(self) -> Dict[str, str]:
        return {
            "x-apikey": self.api_key,
            "Accept": "application/json",
        }

    async def _respect_rate_limit(self) -> None:
        """Sleep if needed to honor the configured per-minute rate limit."""
        async with self._rate_lock:
            now = time.monotonic()
            window_start = now - 60.0
            self._request_times = [t for t in self._request_times if t > window_start]
            if len(self._request_times) >= self.rate_limit:
                oldest = self._request_times[0]
                wait = 60.0 - (now - oldest)
                if wait > 0:
                    logger.debug("VirusTotal rate limit — sleeping %.2fs", wait)
                    await asyncio.sleep(wait)
                    now = time.monotonic()
                    window_start = now - 60.0
                    self._request_times = [t for t in self._request_times if t > window_start]
            self._request_times.append(now)

    async def _get(self, path: str) -> Optional[Dict[str, Any]]:
        """Issue a GET to the VT v3 API.

        Returns the parsed JSON body on 200, ``None`` on 404.

        Raises:
            InvalidKeyError: on 401.
            RateLimitedError: on 429.
            VirusTotalError: on other error responses.
        """
        if not self.is_configured:
            raise VirusTotalError("VirusTotal integration is not configured")

        await self._respect_rate_limit()

        full_url = f"{self.url}{path}"
        try:
            async with httpx.AsyncClient(
                headers=self._get_headers(),
                verify=get_ssl_verify(self.verify_ssl),
                timeout=httpx.Timeout(float(self.timeout), connect=10.0),
            ) as client:
                response = await client.get(full_url)
        except httpx.ConnectError as exc:
            raise VirusTotalError(f"Failed to connect to VirusTotal: {exc}")
        except httpx.TimeoutException as exc:
            raise VirusTotalError(f"Request to VirusTotal timed out: {exc}")
        except httpx.HTTPError as exc:
            raise VirusTotalError(f"HTTP error communicating with VirusTotal: {exc}")

        status = response.status_code
        if status == 200:
            try:
                return response.json()
            except ValueError as exc:
                raise VirusTotalError(f"VirusTotal returned invalid JSON: {exc}")
        if status == 404:
            return None
        if status == 401:
            raise InvalidKeyError()
        if status == 429:
            retry_after_hdr = response.headers.get("Retry-After")
            retry_after: Optional[float] = None
            if retry_after_hdr:
                try:
                    retry_after = float(retry_after_hdr)
                except ValueError:
                    retry_after = None
            raise RateLimitedError(retry_after=retry_after)

        # Generic error path
        try:
            error_data = response.json()
            message = str(error_data.get("error", error_data))
        except ValueError:
            message = response.text
        raise VirusTotalError(f"VirusTotal API error ({status}): {message}", status_code=status)

    def _normalize(self, raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Convert a VT response (or None) into the uniform enrichment shape."""
        if not raw:
            return {
                "found": False,
                "reputation": 0,
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "undetected_count": 0,
                "last_analysis_date": None,
                "raw": {},
                "source": "virustotal",
            }

        data = raw.get("data") or {}
        attrs = data.get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}

        return {
            "found": True,
            "reputation": int(attrs.get("reputation") or 0),
            "malicious_count": int(stats.get("malicious") or 0),
            "suspicious_count": int(stats.get("suspicious") or 0),
            "harmless_count": int(stats.get("harmless") or 0),
            "undetected_count": int(stats.get("undetected") or 0),
            "last_analysis_date": _to_iso8601(attrs.get("last_analysis_date")),
            "raw": raw,
            "source": "virustotal",
        }

    async def lookup_file_hash(self, sha256: str) -> Dict[str, Any]:
        """Look up a file by hash (SHA-256, SHA-1, or MD5 all accepted by VT)."""
        if not sha256:
            raise VirusTotalError("Empty file hash")
        raw = await self._get(f"/api/v3/files/{sha256}")
        return self._normalize(raw)

    async def lookup_url(self, url: str) -> Dict[str, Any]:
        """Look up a URL. Encodes the URL id as base64url-without-padding."""
        if not url:
            raise VirusTotalError("Empty URL")
        url_id = _encode_url_id(url)
        raw = await self._get(f"/api/v3/urls/{url_id}")
        return self._normalize(raw)

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Look up a domain name."""
        if not domain:
            raise VirusTotalError("Empty domain")
        raw = await self._get(f"/api/v3/domains/{domain}")
        return self._normalize(raw)

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Look up an IPv4 or IPv6 address."""
        if not ip:
            raise VirusTotalError("Empty IP address")
        raw = await self._get(f"/api/v3/ip_addresses/{ip}")
        return self._normalize(raw)


# Singleton instance
_virustotal_service: Optional[VirusTotalService] = None


def get_virustotal_service() -> VirusTotalService:
    """Get the global VirusTotal service instance."""
    global _virustotal_service
    if _virustotal_service is None:
        _virustotal_service = VirusTotalService()
    return _virustotal_service


def reset_virustotal_service() -> None:
    """Reset the global VirusTotal service instance (for config changes)."""
    global _virustotal_service
    _virustotal_service = None
