"""FastAPI logging middleware for ECS-compliant request logging."""

import time
import uuid
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ixion.core.logging import (
    set_request_context,
    clear_request_context,
    get_structured_logger,
    generate_request_id,
)


logger = get_structured_logger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs all HTTP requests in ECS format.

    Features:
    - Assigns unique request ID to each request
    - Logs request start and completion
    - Tracks request duration
    - Captures client IP, user agent
    - Integrates with distributed tracing (trace ID from headers)
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate or extract request ID
        request_id = request.headers.get("X-Request-ID") or generate_request_id()

        # Extract trace ID for distributed tracing
        trace_id = (
            request.headers.get("X-Trace-ID") or
            request.headers.get("traceparent", "").split("-")[1] if "-" in request.headers.get("traceparent", "") else None
        ) or request_id

        # Get client IP (handle proxies)
        client_ip = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or
            request.headers.get("X-Real-IP") or
            request.client.host if request.client else "unknown"
        )

        # Set logging context for this request
        set_request_context(
            request_id=request_id,
            client_ip=client_ip,
            trace_id=trace_id,
        )

        # Add request ID to response headers
        start_time = time.time()

        try:
            response = await call_next(request)

            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)

            # Log the request
            logger.http_request(
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=duration_ms,
                user_agent=request.headers.get("User-Agent"),
            )

            # Add headers to response
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Response-Time"] = f"{duration_ms}ms"

            return response

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)

            logger.error(
                f"Request failed: {request.method} {request.url.path}",
                error_type=type(e).__name__,
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": duration_ms,
                },
            )
            raise

        finally:
            clear_request_context()


class AuthLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that adds authenticated user info to logging context.

    Should be added AFTER authentication middleware.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check if user is set on request state (by auth middleware)
        user = getattr(request.state, "user", None)

        if user:
            set_request_context(
                user_id=user.id if hasattr(user, "id") else None,
                username=user.username if hasattr(user, "username") else None,
            )

        return await call_next(request)
