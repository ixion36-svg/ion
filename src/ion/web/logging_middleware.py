"""FastAPI logging middleware for ECS-compliant request logging."""

import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ion.core.logging import (
    clear_request_context,
    generate_request_id,
    get_structured_logger,
    set_request_context,
)

logger = get_structured_logger(__name__)

# Above this, a request is logged as an error and shows up in alerting; above
# the soft threshold it is a warning. Tighten once p99 drops below them.
_SLOW_HARD_MS = 2000
_SLOW_SOFT_MS = 500


def _header(scope_headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    """First value for a header, or None. ASGI header names are lowercase bytes."""
    for k, v in scope_headers:
        if k == name:
            return v.decode("latin-1")
    return None


def _trace_id(headers: list[tuple[bytes, bytes]], request_id: str) -> str:
    """Caller-supplied trace id, else the W3C traceparent's trace-id, else our own.

    Written as explicit branches on purpose. The single-expression form
    `a or b if cond else None` parses as `(a or b) if cond else None`, which
    dropped X-Trace-ID entirely whenever traceparent was absent -- the common
    case -- so a caller's trace id never survived. See CLAUDE.md.
    """
    supplied = _header(headers, b"x-trace-id")
    if supplied:
        return supplied
    traceparent = _header(headers, b"traceparent") or ""
    parts = traceparent.split("-")
    if len(parts) >= 2 and parts[1]:
        return parts[1]
    return request_id


def _client_ip(headers: list[tuple[bytes, bytes]], client) -> str:
    """Proxy headers win over the socket peer; the peer is the fallback, not a gate.

    Same precedence trap as _trace_id: the previous single-expression form was
    gated on `if request.client`, so behind a proxy that left no client in the
    scope, X-Forwarded-For was discarded and the IP logged as "unknown".
    """
    forwarded = _header(headers, b"x-forwarded-for")
    if forwarded:
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    real_ip = _header(headers, b"x-real-ip")
    if real_ip:
        return real_ip
    if client:
        return client[0]
    return "unknown"


class RequestLoggingMiddleware:
    """Logs all HTTP requests in ECS format.

    Pure ASGI rather than BaseHTTPMiddleware: that base class builds a Request
    object and runs the rest of the app in a separate task for every layer, and
    measured on this stack it was the most expensive layer in the chain for what
    is only timing and logging.

    - Assigns a unique request ID to each request
    - Tracks request duration and trips a slow-request tripwire
    - Captures client IP (proxy-aware) and user agent
    - Propagates a distributed trace ID from X-Trace-ID or W3C traceparent
    """

    def __init__(self, app):
        self.app = app
        # Server-side timing is an enumeration oracle: login runs bcrypt for a
        # real account and short-circuits for an absent one, a ~200ms gap that
        # this header reports free of network jitter -- defeating the uniform
        # login response. Developers keep it; deployments do not.
        from ion.core.config import get_config

        _cfg = get_config()
        self._expose_timing = bool(_cfg.dev_mode or _cfg.debug_mode)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = scope["headers"]
        request_id = _header(headers, b"x-request-id") or generate_request_id()

        set_request_context(
            request_id=request_id,
            client_ip=_client_ip(headers, scope.get("client")),
            trace_id=_trace_id(headers, request_id),
        )

        start_time = time.time()
        status_code = 500
        rid = request_id.encode("latin-1")

        async def send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                duration_ms = int((time.time() - start_time) * 1000)
                extra = [(b"x-request-id", rid)]
                if self._expose_timing:
                    extra.append(
                        (b"x-response-time", f"{duration_ms}ms".encode("latin-1"))
                    )
                message = {**message, "headers": [*message.get("headers", []), *extra]}
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
            duration_ms = int((time.time() - start_time) * 1000)
            method, path = scope["method"], scope["path"]

            logger.http_request(
                method=method,
                path=path,
                status=status_code,
                duration_ms=duration_ms,
                user_agent=_header(headers, b"user-agent"),
            )

            if duration_ms >= _SLOW_HARD_MS:
                logger.error(
                    f"SLOW REQUEST (>2s): {method} {path} {status_code} {duration_ms}ms",
                )
            elif duration_ms >= _SLOW_SOFT_MS:
                logger.warning(
                    f"Slow request (>500ms): {method} {path} {status_code} {duration_ms}ms",
                )

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.error(
                f"Request failed: {scope['method']} {scope['path']}",
                error_type=type(e).__name__,
                extra={
                    "method": scope["method"],
                    "path": scope["path"],
                    "duration_ms": duration_ms,
                },
            )
            raise

        finally:
            clear_request_context()


class AuthLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs authentication events.

    This works with the auth system to log:
    - Login attempts
    - Failed authentications
    - Session events
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Log authentication failures
        if response.status_code == 401:
            logger.security_event(
                event_type="authentication_failure",
                severity="medium",
                outcome="failure",
                extra={
                    "path": request.url.path,
                    "method": request.method,
                },
            )
        elif response.status_code == 403:
            logger.security_event(
                event_type="authorization_failure",
                severity="medium",
                outcome="failure",
                extra={
                    "path": request.url.path,
                    "method": request.method,
                },
            )

        return response
