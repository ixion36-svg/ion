"""Shared HTTP helper for REST-style executor adapters.

All REST adapters share the same retry / backoff / timeout / SSL
behaviour.  This module centralises it so each adapter stays small and
focused on building its request payload.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


# Retry schedule — 3 attempts total, exponential backoff (1s, 2s) between.
_RETRY_BACKOFFS = (1.0, 2.0)


@dataclass
class HttpCallResult:
    """Return value of :func:`post_with_retry`."""

    status_code: Optional[int]
    response_json: dict
    response_text: str
    error: Optional[str]

    @property
    def success(self) -> bool:
        return (
            self.status_code is not None
            and 200 <= self.status_code < 300
            and self.error is None
        )


def _ssl_verify(config, per_adapter_flag: bool) -> bool | str:
    """Resolve SSL-verify value, honouring config.ca_bundle if set."""
    try:
        from ion.core.config import get_ssl_verify
        return get_ssl_verify(per_adapter_flag)
    except Exception:
        return per_adapter_flag


async def post_with_retry(
    url: str,
    *,
    json_body: dict,
    headers: dict,
    timeout_s: float,
    verify_ssl: bool | str,
) -> HttpCallResult:
    """POST ``json_body`` to ``url`` with retry on connection errors / 5xx.

    Up to 3 attempts total with exponential backoff (1s, 2s).  4xx
    responses are returned immediately without retry (they indicate a
    client-side problem that retrying will not fix).

    Returns an :class:`HttpCallResult` describing the final outcome;
    never raises for network / HTTP errors (the error is captured in the
    ``error`` field).  Raising is reserved for programmer mistakes.
    """
    last_error: Optional[str] = None
    last_status: Optional[int] = None
    last_text: str = ""
    last_json: dict = {}

    for attempt in range(3):
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(timeout_s, connect=min(timeout_s, 10.0)),
                verify=verify_ssl,
            ) as client:
                resp = await client.post(url, json=json_body, headers=headers)
        except (httpx.ConnectError, httpx.ReadError, httpx.TimeoutException) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            last_status = None
            logger.warning("Executor HTTP attempt %d failed: %s", attempt + 1, last_error)
            if attempt < len(_RETRY_BACKOFFS):
                await asyncio.sleep(_RETRY_BACKOFFS[attempt])
                continue
            break
        except httpx.HTTPError as exc:
            # Other unexpected httpx errors — treat as non-retryable.
            last_error = f"{type(exc).__name__}: {exc}"
            last_status = None
            break

        last_status = resp.status_code
        last_text = resp.text
        try:
            last_json = resp.json() if resp.content else {}
            if not isinstance(last_json, dict):
                last_json = {"body": last_json}
        except ValueError:
            last_json = {}

        if 200 <= resp.status_code < 300:
            return HttpCallResult(
                status_code=resp.status_code,
                response_json=last_json,
                response_text=last_text,
                error=None,
            )

        if 500 <= resp.status_code < 600 and attempt < len(_RETRY_BACKOFFS):
            last_error = f"HTTP {resp.status_code}: {last_text[:200]}"
            logger.warning(
                "Executor HTTP attempt %d returned %d, retrying",
                attempt + 1, resp.status_code,
            )
            await asyncio.sleep(_RETRY_BACKOFFS[attempt])
            continue

        # 4xx or final 5xx — no more retries.
        last_error = f"HTTP {resp.status_code}: {last_text[:200]}"
        break

    return HttpCallResult(
        status_code=last_status,
        response_json=last_json,
        response_text=last_text,
        error=last_error or "Unknown HTTP error",
    )


def resolve_verify(config, per_adapter_flag: bool) -> bool | str:
    """Public wrapper for SSL verify resolution (keeps adapters thin)."""
    return _ssl_verify(config, per_adapter_flag)


__all__ = ["HttpCallResult", "post_with_retry", "resolve_verify"]
