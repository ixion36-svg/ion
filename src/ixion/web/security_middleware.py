"""Security monitoring middleware for FastAPI."""

from typing import Callable, Optional

from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from ixion.core.logging import get_structured_logger
from ixion.services.security_service import (
    SecurityDetectionService,
    RequestContext,
)
from ixion.storage.database import get_engine, get_session_factory
from ixion.core.config import get_config


logger = get_structured_logger(__name__)


def get_client_ip(request: Request) -> str:
    """Extract client IP from request, handling proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    if request.client:
        return request.client.host

    return "unknown"


class SecurityMonitoringMiddleware(BaseHTTPMiddleware):
    """Middleware for detecting and logging security threats.

    Features:
    - Analyzes requests for attack patterns
    - Blocks requests from blocked IPs
    - Records security events
    - Integrates with the security dashboard
    """

    # Trusted IPs that are never blocked or scanned (localhost/development)
    TRUSTED_IPS = (
        "127.0.0.1",
        "localhost",
        "::1",  # IPv6 localhost
    )

    # Paths excluded from IP blocking and attack detection
    # (admins must be able to access dashboard to unblock, templates/extract contain code-like content)
    EXCLUDED_PATHS = (
        "/security",
        "/api/security/",
        "/static/",
        "/login",
        "/api/auth/login",
        "/api/extract/",  # Extract endpoints analyze user documents which may contain code
        "/extract",
        "/api/templates",  # Templates contain Jinja2 syntax like {{ }} which triggers patterns
        "/templates",
        "/api/collections",  # Collection management
    )

    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled

        # Initialize database connection
        try:
            config = get_config()
            self.engine = get_engine(config.db_path)
            self.session_factory = get_session_factory(self.engine)
        except Exception as e:
            logger.error(f"Failed to initialize security middleware: {e}")
            self.engine = None
            self.session_factory = None

    def _is_excluded_path(self, path: str) -> bool:
        """Check if path is excluded from security blocking."""
        for excluded in self.EXCLUDED_PATHS:
            if path == excluded or path.startswith(excluded):
                return True
        return False

    def _is_trusted_ip(self, ip: str) -> bool:
        """Check if IP is in the trusted list (localhost/development)."""
        return ip in self.TRUSTED_IPS

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.enabled or not self.session_factory:
            return await call_next(request)

        client_ip = get_client_ip(request)

        # Skip all security checks for trusted IPs (localhost)
        if self._is_trusted_ip(client_ip):
            return await call_next(request)

        session = self.session_factory()
        try:
            security_service = SecurityDetectionService(session)

            # Check if IP is blocked (but allow excluded paths like security dashboard)
            if security_service.is_ip_blocked(client_ip) and not self._is_excluded_path(request.url.path):
                logger.security_event(
                    action="blocked_ip_request",
                    outcome="blocked",
                    details={"ip": client_ip, "path": request.url.path},
                )
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Access denied"},
                )

            # Skip attack detection for excluded paths (security dashboard, static files, etc.)
            if self._is_excluded_path(request.url.path):
                return await call_next(request)

            # Build request context
            body = None
            if request.method in ("POST", "PUT", "PATCH"):
                try:
                    body_bytes = await request.body()
                    body = body_bytes.decode("utf-8", errors="ignore")[:10000]  # Limit size
                except Exception:
                    pass

            ctx = RequestContext(
                source_ip=client_ip,
                request_path=request.url.path,
                request_method=request.method,
                user_agent=request.headers.get("User-Agent"),
                query_string=str(request.query_params),
                body=body,
                headers=dict(request.headers),
                user_id=getattr(getattr(request.state, "user", None), "id", None),
                username=getattr(getattr(request.state, "user", None), "username", None),
            )

            # Analyze request for attacks
            detections = security_service.analyze_request(ctx)

            # Record and handle detections
            should_block = False
            for detection in detections:
                # Capture raw data for forensics
                raw_data = {
                    "path": ctx.request_path,
                    "query_string": ctx.query_string if ctx.query_string else None,
                    "body": ctx.body[:2000] if ctx.body else None,  # Limit stored body size
                    "matched_content": detection.matched_content if hasattr(detection, 'matched_content') and detection.matched_content else None,
                }
                # Remove empty values
                raw_data = {k: v for k, v in raw_data.items() if v}

                event = security_service.record_event(ctx, detection, raw_data=raw_data)
                session.commit()

                logger.security_event(
                    action=detection.event_type.value if detection.event_type else "unknown",
                    outcome="detected",
                    details={
                        "ip": client_ip,
                        "path": request.url.path,
                        "confidence": detection.confidence_score,
                        "patterns": detection.matched_patterns[:3],  # Limit logged patterns
                    },
                )

                if detection.should_block:
                    should_block = True
                    # Block the IP
                    security_service.block_ip(
                        ip_address=client_ip,
                        reason=f"Automatic block: {detection.title}",
                        duration_minutes=60,
                        security_event_id=event.id,
                    )
                    session.commit()

            if should_block:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Request blocked due to security policy"},
                )

            # Continue with request
            response = await call_next(request)
            return response

        except Exception as e:
            logger.error(f"Security middleware error: {e}", exc_info=True)
            # Don't block requests on middleware errors
            return await call_next(request)

        finally:
            session.close()


class RateLimitSecurityMiddleware(BaseHTTPMiddleware):
    """Middleware that records rate limit violations as security events."""

    def __init__(self, app):
        super().__init__(app)

        try:
            config = get_config()
            self.engine = get_engine(config.db_path)
            self.session_factory = get_session_factory(self.engine)
        except Exception:
            self.engine = None
            self.session_factory = None

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Check if rate limited (429 status)
        if response.status_code == 429 and self.session_factory:
            session = self.session_factory()
            try:
                security_service = SecurityDetectionService(session)
                client_ip = get_client_ip(request)

                security_service.record_rate_limit_exceeded(
                    source_ip=client_ip,
                    request_path=request.url.path,
                    user_agent=request.headers.get("User-Agent"),
                )
                session.commit()

            except Exception as e:
                logger.error(f"Error recording rate limit event: {e}")
            finally:
                session.close()

        return response
